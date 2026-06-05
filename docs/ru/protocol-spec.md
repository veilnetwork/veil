# Спецификация протокола OVL1

Версия: **1** (magic `0x4F564C31`), minor = 1.

> Для архитектурного обзора — [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).
> Для быстрой справки по wire-формату — [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

---

## 1. Идентификация

### 1.1 node_id

```text
node_id = BLAKE3(raw_public_key_bytes)   // 32 байта
```

Реализация: `cfg::model::NodeId::from_public_key(algo, base64_pubkey)`.

Свойства:
- Стабильный глобальный идентификатор — не зависит от IP, местоположения, транспорта
- Привязан к криптографическому ключу
- Алгоритм хэширования: BLAKE3, вход: raw bytes публичного ключа (не base64-строка)
- Представляется как 64-символьный hex-string в CLI и конфиге

### 1.2 app_id

```text
app_id = BLAKE3-derive_key(
    context = "veil.app_id.v1",
    ikm     = node_id || ns_len(u32 BE) || app_namespace
                       || name_len(u32 BE) || app_name
)     // 32 байта
```

`app_namespace` и `app_name` — UTF-8 строки произвольного содержания, выбираемые
разработчиком приложения (convention: reverse-DNS, например `"com.example.chat"`
+ `"main"`). На wire-уровне ограничены 255 байт каждая (см. §9.3 `AppBind`).

**Length-prefixes и domain separator обязательны** — без них наивная конкатенация
даёт коллизии: `("foo","bar")` и `("fo","obar")` оба склеиваются в `"foobar"`
и дают одинаковый digest.  v1 derivation гарантирует уникальность.

Для IPC-приложений в ephemeral-режиме (по умолчанию) формула расширена
16-байтным `client_token`, выдаваемым узлом в `AppHelloOk`:

```text
ephemeral_app_id = BLAKE3-derive_key(
    context = "veil.ephemeral_app_id.v1",
    ikm     = node_id || client_token(16) || ns_len(u32 BE) || app_namespace
                                           || name_len(u32 BE) || app_name
)
```

Это делает `app_id` уникальным per-connection — два процесса на одном узле,
биндящие один и тот же `(namespace, name)`, получают разные адреса. Для
well-known сервисов используется стабильная форма выше (через `bind_named`).

Адрес конечной точки приложения:

```
AppAddress {
  node_id:     [u8; 32],    // Узел, на котором запущено приложение
  app_id:      [u8; 32],    // Идентификатор приложения
  endpoint_id: u32,         // Порт внутри приложения (1..65535)
}
```

### 1.3 content_id

```text
content_id = BLAKE3(payload_bytes)   // 32 байта
```

Используется для дедупликации сообщений в transit.

---

## 2. Wire-формат фреймов

### 2.1 Заголовок фрейма (FrameHeader)

Фиксированный заголовок — **24 байта**:

```text
Offset  Len  Тип    Описание
------  ---  -----  ---------
  0      4   u32 BE Magic = 0x4F564C31 ("OVL1")
  4      1   u8     Version = 1
  5      1   u8     Family (см. таблицу ниже)
  6      2   u16 BE msg_type (зависит от Family)
  8      2   u16 BE flags (биты приоритета, шифрование, ACK-request)
 10      2   u16 BE header_len = 24
 12      4   u32 BE body_len (0 .. MAX_FRAME_BODY = 16 МиБ; default listener cap = 1 МиБ)
 16      4   u32 BE stream_id (мультиплексирование эндпоинтов)
 20      4   u32 BE request_id (корреляция RPC)
 24      ?   bytes  Body (body_len байт)
```

### 2.2 Флаги фрейма (flags, биты)

| Бит | Имя | Описание |
|-----|-----|----------|
| 0..1 | priority | 0=RT, 1=Interactive, 2=Bulk, 3=Background |
| 2 | encrypted | Тело зашифровано ChaCha20-Poly1305 |
| 3 | require_ack | Запрос подтверждения доставки |
| 4..15 | reserved | Зарезервировано, должны быть 0 |

### 2.3 Family — семейства протоколов

| Family | Число | Назначение |
|--------|-------|------------|
| Session | 0 | OVL1 handshake, keepalive, rekey, resumption ticket, padding |
| Control | 1 | Ping, NeighborOffer, RouteProbe, NAT, Keepalive, Backpressure, Epidemic |
| Discovery | 2 | DHT FindNode, FindValue, Store, Delete, Attachment/Mailbox/AppEndpoint lookup |
| Delivery | 3 | Mailbox Put/Fetch/Ack, DeliveryForward, Status, Chunks, Transit, RecursiveRelay |
| App | 4 | Потоки приложений (открытие, данные, закрытие, real-time) |
| Mesh | 5 | Локальная UDP-сеть (беаконы, форвард) |
| LocalApp | 6 | IPC для локальных приложений |
| Tunnel | 7 | TUN/TAP IP-туннель |
| Routing | 8 | RouteAnnounce/Withdraw, RouteRequest/Response, PoW, Recursive*, VersionVectorSync |
| Diag | 9 | Диагностика: DiagPing, DiagPong, TraceProbe, TraceHop |
| RelayChain | 10 | Onion-encrypted relay chain hop |
| PeerExchange | 11 | PEX random-walk: Walk, Challenge, Response, Result |

---

## 3. Session Plane (Family 0)

### 3.1 Handshake

OVL1-handshake — асимметричный, инициируемый клиентом. Последовательность:

```
Initiator                              Responder
    │── Hello ──────────────────────────►│   OVL1 version + node_id
    │◄─ Hello ───────────────────────────│
    │── Identity ─────────────────────►│   pubkey + nonce + algo + ML-KEM ek
    │◄─ Identity ────────────────────────│
    │── Capabilities ─────────────────►│   role bits + feature flags
    │◄─ Capabilities ─────────────────────│
    │── KeyAgreement ─────────────────►│   ephemeral X25519 pubkey
    │◄─ KeyAgreement ─────────────────────│
    │── SessionConfirm ───────────────►│   session_id + MAC
    │◄─ SessionConfirm ───────────────────│
    │── Attach (optional) ─────────────►│   (leaf → gateway)
    │   [CONNECTED]                      │
```

### 3.2 HelloPayload (24 байта)

```text
[0..2]   ovl1_version   u16 BE = 1
[2..34]  node_id        [u8; 32]
```

### 3.3 IdentityPayload

```text
[0]                  algo           u8  (IdentityPayload: 0=Ed25519, 2=Falcon512, 3=Ed25519+Falcon512, 4=Ed25519+Falcon1024;
                                         session handshake: 1=Ed25519, 2=Falcon512)
[1..3]               pk_len         u16 BE
[3..3+pk]            public_key     bytes
[3+pk]               nonce_len      u8
[4+pk..4+pk+n]       nonce          bytes  (PoW-nonce hex-string)
[4+pk+n..+32]        node_id        [u8; 32]  (must equal BLAKE3(public_key))
[+2]                 mlkem_pk_len   u16 BE  (0 = не передаётся)
[..]                 mlkem_pk       bytes   (1184 Б для ML-KEM-768)
```

### 3.4 CapabilitiesPayload (3 байта)

```text
[0]     roles_supported      u8  (bit 0 = LEAF, bit 3 = CORE; остальные — зарезервированы)
[1]     flags                u8  (cap_flags: CAN_RELAY=0x01,
                                  SUPPORTS_SOVEREIGN_IDENTITY=0x02)
[2]     discovery_mode       u8  (0 = Public, 1 = ContactsOnly,
                                  2 = IntroductionOnly; unknown values
                                  трактуются как IntroductionOnly —
                                  forward-compat default)
```

**Backward-compat:** legacy peers отправляют 2 байта (без `discovery_mode`); decoder default'ит missing byte на `0` (Public) — legacy peers не имели концепции opt-in privacy и были фактически Public. Decoder принимает `>= 2` байт.

**discovery_mode семантика:**

- `Public` — peer хочет быть discoverable через DHT-walk; FIND_NODE responses от других узлов будут включать его.
- `ContactsOnly` — peer должен быть исключён из FIND_NODE responses; reachable только через direct sessions с already-handshake'd контактами или pre-shared bootstrap.
- `IntroductionOnly` — то же что `ContactsOnly` для FIND_NODE; дополнительно RouteResponse строго обязан стрипать `transports[]` (см. §3.6).

Legacy fields:
- Role bits `RELAY (0x02)`, `GATEWAY (0x04)`, `CORE_ROUTER (0x10)` — удалены.
- Cap flags `CAN_MAILBOX=0x02`, `CAN_GATEWAY_LOCAL_MESH=0x04`, `CAN_PARTICIPATE_DHT=0x08`, `CAN_ACCEPT_APP_STREAMS=0x10`, `CAN_STORE=0x20`, `SUPPORTS_TRANSIT=0x40` — никогда не читались, удалены.
- Wire-format ужат с 12 байт (legacy) → 2 байт → 3 байт.

### 3.5 SessionKeys (производные ключи)

После обмена ephemeral **X25519** (это NOT identity key — identity, Ed25519/Falcon-512, используется только для подписи в `IdentityPayload`):

```
shared_secret = X25519(my_ephemeral_priv, peer_ephemeral_pub)

salt = local_node_id XOR remote_node_id           // commutative — обе стороны
                                                  // получают одинаковый salt
ikm  = shared_secret
info = "ovl1-session-v1"

[key_a ‖ key_b ‖ session_id] = HKDF-SHA256(salt, ikm, info, len=96)

(tx_key, rx_key) = if local_node_id <= remote_node_id  → (key_a, key_b)
                   else                                 → (key_b, key_a)
```

`tx_key` — для шифрования исходящих фреймов; `rx_key` — для расшифровки входящих.
Lex-order по `node_id` гарантирует, что у инициатора и у респондента
`tx_key`/`rx_key` поменены местами: alice.tx == bob.rx и наоборот.

Фреймы шифруются **ChaCha20-Poly1305** (по 32-байтному ключу `tx_key` /`rx_key`,
12-байтный счётчик-nonce per-direction; AAD — заголовок фрейма).

`session_id` (32 байта) — публичный идентификатор, кладётся в
`SessionConfirmPayload` и используется как chain-salt для последующих rekey.

Identity-key (Ed25519/Falcon-512) в этой derivation **не участвует**: forward
secrecy — компрометация long-term identity ключа не раскрывает прошлые сессии.

### 3.6 KeepalivePayload

```text
[0..8]   timestamp_secs  u64 BE
```

Отправляется с интервалом `session.keepalive_interval_secs`. При отсутствии активности дольше `session.idle_timeout_secs` — сессия закрывается.

### 3.7 Rekey (перемена ключей)

Инициируется при превышении `REKEY_BYTES_THRESHOLD` = 128 ГиБ или `REKEY_TIME_THRESHOLD_SECS` = 32 дня (2 764 800 с). Оба порога настраиваются в конфиге: `[session] rekey_bytes_threshold` и `[session] rekey_time_threshold_secs` — высокочувствительные деплои могут опустить их явно. Байтовый порог `MLKEM_REKEY_BYTES_THRESHOLD` теперь равен 128 ГиБ (как и `REKEY_BYTES_THRESHOLD`); от основных порогов отличается только временной `MLKEM_REKEY_TIME_THRESHOLD_SECS` = 1 час, который выравнивает forward-secrecy окно X25519 сессионного ключа с ML-KEM E2E-ключом.

```
Initiator ── RekeyInit ──► Responder   (новый ephemeral X25519 pubkey)
Initiator ◄─ RekeyAck ──── Responder   (ответный ephemeral X25519 pubkey)

new_shared = X25519(new_ephemeral_priv, peer_new_ephemeral_pub)
salt       = session_id XOR local_node_id XOR remote_node_id
                                    └ chain-salt связывает новые ключи с историей сессии
info       = "ovl1-session-rekey-v1"
[key_a ‖ key_b ‖ new_session_id] = HKDF-SHA256(salt, new_shared, info, len=96)
(tx_key, rx_key) — swap по lex-order node_id, как в §3.5
```

---

## 4. Control Plane (Family 1)

### 4.1 RouteProbePayload

```text
[0..4]   probe_id      u32 BE
[4..12]  timestamp_ms  u64 BE  (локальное время отправителя)
```

### 4.2 RouteReplyPayload

```text
[0..4]   probe_id      u32 BE  (эхо из RouteProbe)
[4..12]  timestamp_ms  u64 BE  (эхо)
[12..16] rtt_ms        u32 BE  (RTT измеренный responder'ом; 0 = неизвестно)
[16]     congestion    u8      (0=free … 255=saturated)
```

### 4.3 NeighborOfferPayload

```text
[0..32]  node_id    [u8; 32]
[32..34] addr_len   u16 BE
[34..N]  addr       bytes  (транспортный URI)
[N]      flags      u8     (возможности соседа)
```

### 4.4 EpidemicPayload (эпидемическое вещание)

```text
[0..16]          msg_id      [u8; 16]  (случайный 128-битный ID)
[16]             ttl         u8        (оставшийся hop-count)
[17..49]         origin      [u8; 32]  (node_id отправителя)
[49..51]         payload_len u16 BE
[51..51+len]     payload     bytes
```

Каждый узел, получивший новое (непросмотренное) сообщение, доставляет его локально и форвардит к **K случайным соседям** с `ttl - 1`. Дедупликация по `msg_id`.

### 4.5 NAT — NatProbeRequestPayload / NatProbeReplyPayload

```text
[0..32]  initiator_node_id  [u8; 32]
[32..36] session_token       u32 BE
[36..38] candidate_count     u16 BE
[38..]   candidates[]        NatCandidate (variable)
```

**NatCandidate**:

```text
[0]      atyp             u8     (адресный тип: 4=IPv4, 6=IPv6, и др.)
[1]      candidate_type   u8     (0=host, 1=server-reflexive, 2=relay)
[2..6]   priority         u32 BE
[6..6+L] addr             bytes  (L зависит от atyp)
[6+L..]  port             u16 BE
```

---

## 5. Discovery Plane (Family 2) — DHT (Kademlia)

### 5.1 FindNode (V2 only — V1 removed)

V1 `FindNode` (slot 0) and `FindNodeResponse` (slot 8) — wire layout:
target+k → `Vec<NodeContact{node_id, transport}>` — were dropped.
V1 returned a transport per contact in the same RTT, which leaked the
routing graph en masse and made network-wide enumeration trivially
cheap.  All FIND_NODE traffic now goes through V2 + `ResolveTransport`
(§5.4.1).  Senders that emit slots 0 / 8 fail `DiscoveryMsg::try_from`
→ `Violation` in the dispatcher.

**`NodeContact`** is retained as a wire-helper for the `FindValue` not-found branch:

```text
[0..32]  node_id       [u8; 32]
[32..34] transport_len u16 BE
[34..N]  transport     bytes  (URI строка)
```

Начиная с **C-06** ветка «не найдено» у `FindValue` обнуляет это поле
(`transport_len = 0`, пустой URI): как и FIND_NODE V2, она возвращает **только
node_id**, а запрашивающая сторона до-разрешает транспорт каждого узла по
требованию через `ResolveTransport` (§5.4.1). Это закрывает ту же массовую
утечку графа маршрутизации и на пути value-lookup; итеративный/рекурсивный обход
всё равно сходится, потому что транспорты разрешаются hop-by-hop, а не
встраиваются в ответ (см. регрессию на цепочке из 64 узлов в
`crates/veil-dht/src/iterative.rs`).

#### 5.2.1 discovery_mode filter + half-cap

The V2 FIND_NODE (`handle_find_node_v2`) and `FindValue` not-found
fallback both apply two levels of filtering before returning contacts
(via the shared `ranked_public_contacts` helper):

1. **Public-only filter:** peers с `discovery_mode != Public` (declared в `CapabilitiesPayload.discovery_mode` при handshake) исключаются из ответа. Это закрывает enumeration-leak для opt-in privacy узлов: `ContactsOnly` / `IntroductionOnly` peer не появится в ответах других узлов на FIND_NODE — и поэтому невидим для DHT-walk сканеров.

2. **Half-cap:** возвращается не более `min(K_requested, K_local, ceil(N_public / 2))` контактов, где `N_public` — количество Public peers в нашем routing table. Заставляет атакующего, перечисляющего Public-сеть, сделать **минимум 2× больше FIND_NODE-запросов** для покрытия полной carto. Smallest case: с 1 Public peer возвращается 1 (Kademlia connectivity preserved).

Аналогичная фильтрация применяется в:

- `handle_find_value::FindValueResponse::Nodes` (closest-nodes fallback)
- `handle_recursive_query::FIND_NODE` (через `find_closest_public_node_ids` helper)

**НЕ фильтруется** internal routing (`find_closest_nodes` для next-hop selection, NeighborOffer) — там фильтр сломал бы маршрутизацию через privacy-opt-in узлы как relay.

**Threat model:** scanner-resistance — passive enumeration по DHT FIND_NODE. Ранее сканер одним FIND_NODE получал K transports → ~10 RTT enumeration всех Public-узлов в /20 keyspace → полная карта адресов за минуты. Half-cap + Public-only делает enumeration ≥ 2× медленнее и невозможным для opt-in privacy узлов вообще.

**Limitation:** Public-узлы (default config) по-прежнему перечисляемы (хотя порциями ≤50%). Для полного decoupling routing graph от address graph — см. Decoupled transport resolution / hidden services (planned).

### 5.3 StorePayload

```text
[0..32]  key       [u8; 32]
[32..36] ttl_secs  u32 BE
[36..40] value_len u32 BE
[40..]   value     bytes
```

### 5.4 AnnounceAttachmentPayload

Объявление leaf → gateway, публикуется в DHT. Точный формат — [`proto/discovery.rs::AnnounceAttachmentPayload`](../../crates/veil-proto/src/discovery.rs):

```text
[0..32]   node_id          [u8; 32]
[32]      role             u8          (NodeRole: 0x01=Leaf, 0x08=Core)
[33..37]  realm_id         u32 BE
[37..41]  epoch            u32 BE      (монотонный счётчик через реконнекты)
[41..49]  expires_at       u64 BE      (Unix-секунды)
[49]      gateway_count    u8          (≤ MAX_GATEWAYS = 32)
[50]      mailbox_count    u8          (≤ MAX_MAILBOXES = 32)
[51..]    gateways[]       GatewayRef × gateway_count (38 байт каждый)
[..]      mailboxes[]      MailboxRef × mailbox_count (40 байт каждый)
[..]      seq_no           u64 BE      (больший seq_no выигрывает при конфликте)
[..]      sig_len          u16 BE      (0 = unsigned)
[..]      signature        bytes       (Ed25519 = 64 Б, Falcon-512 = переменно)
[..]      (optional TLV)   EphemeralEndpoint
```

Подпись покрывает всё от `node_id` до `seq_no` включительно (тело, которое возвращает `signable_body()`).

### 5.4.1 V2 FIND_NODE + ResolveTransport

**Wire-protocol.** `DiscoveryMsg` слоты 10-14:

| msg_type | Имя | Body |
|---|---|---|
| 10 | `FindNodeV2` | `FindNodeV2Payload` (32 байт target + 1 байт k) |
| 11 | `FindNodeV2Response` | `FindNodeV2Response` (count u8 + node_ids `[u8; 32] × count`) |
| 12 | `ResolveTransport` | `ResolveTransportPayload` (52 байт: 32 node_id + 4 time_bucket BE + 16 pow_nonce) |
| 13 | `ResolveTransportResponse` | `ResolveTransportResponse` — carries `Option<SignedTransportAnnouncement>` |
| 14 | `AnnounceTransport` | `SignedTransportAnnouncement` — fire-and-forget post-handshake gossip |

**FindNodeV2Response** (variable):
```text
[0]                  count       u8  (≤ MAX_NODES_PER_RESPONSE = 32)
[1..1+count*32]      node_ids    [u8; 32] × count
```

**Нет transport-полей** (в отличие от удалённой V1 — см. §5.1). Caller знает только node_id'ы, должен отдельно вызвать `ResolveTransport` для каждого, чей transport ему действительно нужен.

**ResolveTransportResponse** (variable):
```text
[0..32]    node_id           [u8; 32]    — echo для caller-correlation
[32]       found             u8          (0 = not found, 1 = found)
если found == 1:
  [33..35]   transport_len   u16 BE
  [35..N]    transport       UTF-8 bytes
  [N..N+8]   observed_at     u64 BE      (Unix-секунды; resolver ставит при insert
                                            в свой Contact, типично — handshake-complete time)
```

`not_found` возвращается когда:
- У resolver'a нет `Contact` для запрошенного `node_id` в routing table.
- Контакт есть, но `discovery_mode != Public` (privacy-фильтр — non-Public peer's существование не подтверждается через этот RPC; aggregate с unknown-case намеренный — сливать "знаю, но не скажу" даёт атакующему signal).

**Threat-model.** Ранее любой FIND_NODE одним RTT возвращал K transports → массовый scan строит cargo IP за O(N/K) RTT (~10 RTT для 200 Public-узлов в /20 keyspace). DHT-walker теперь использует V2 по умолчанию — каждый transport требует отдельный RPC → cumulative cost O(N) RTT, **~10× медленнее**. PoW-gate + signed responses добавляют per-resolve CPU cost (~17ms BLAKE3) + cache-poisoning resistance.

**Status:** wire-types + handlers + in-memory cache + V2-flow integrated в `NetworkPeerQuerier`. **Defense активна** — outbound DHT-walks используют V2-flow по умолчанию (`FindNodeV2 → node_ids → cache lookup → ResolveTransport(id) on miss`). V1 удалён — wire слоты 0/8 → `Violation`.

**PoW gate.** `ResolveTransportPayload`:

```text
[0..32]    node_id      [u8; 32]   — what to resolve
[32..36]   time_bucket  u32 BE     — `unix_secs() / RESOLVE_POW_BUCKET_SECONDS`
[36..52]   pow_nonce    [u8; 16]   — solution
```

The PoW input hash is

```text
BLAKE3( "epic475.4b/resolve_pow/v1" || requester_node_id[32] ||
         target_node_id[32] || time_bucket_be[4] || pow_nonce[16] )
```

`requester_node_id` is the OVL1-session-authenticated `peer_id` on the responder (not on the wire — taken from session context).  Server accepts iff `leading_zero_bits(hash) ≥ RESOLVE_POW_DIFFICULTY` AND `|time_bucket − now_bucket| ≤ RESOLVE_POW_TIME_WINDOW_BUCKETS`.  Defaults: `RESOLVE_POW_DIFFICULTY = 16` (median ~7 ms client mining on a fast x86 core, ~14 ms on low-end ARM); `RESOLVE_POW_BUCKET_SECONDS = 60`; `RESOLVE_POW_TIME_WINDOW_BUCKETS = 1` (≈ 120 s replay window).

PoW failure (invalid solution OR stale bucket OR wrong target / wrong requester binding) → silent `not_found` response, NOT a `Violation` — verification cost is one BLAKE3 hash (~1 µs) so per-peer dht_quota already bounds CPU spend; raising failures to violations would create a clock-drift false-positive eviction path.  Legacy senders without the PoW fields (32-byte payload) fail decode → `Violation` from the dispatcher.

Cumulative attacker cost goes from `O(N) RTT` to `O(N) × ~7 ms CPU` per probed `node_id` — for a `/20` keyspace (~200 Public peers) that's ~1.5 s of single-core mining for one full enumeration sweep, and the cost scales linearly with target set size while honest clients pay it only once per cache miss.

**Signed responses.** `ResolveTransportResponse.transport: Option<String>` carries `Option<SignedTransportAnnouncement>`:

```text
[0..32]    node_id          [u8; 32]
[32..64]   identity_pubkey  [u8; 32]   Ed25519 raw pubkey
[64..128]  signature        [u8; 64]   Ed25519 signature
[128..136] expiry_unix      u64 BE
[136..138] transport_len    u16 BE
[138..N]   transport        UTF-8 (≤ MAX_TRANSPORT_URI_LEN = 256)
```

The signing input is

```text
BLAKE3( "epic475.4c/transport_announce/v1" || node_id ||
         expiry_unix_be || transport_len_be || transport_utf8 )
```

Each node mints its own bundle at startup (validity = 30 days; `ANNOUNCEMENT_VALIDITY_SECS`) and **gossips it via `DiscoveryMsg::AnnounceTransport` (slot 14) on every handshake-complete** (one fire-and-forget frame per session, both inbound and outbound paths).  Receivers verify and store under `transport_announcements: HashMap<node_id, …>` on `KademliaService`; `handle_resolve_transport` returns the cached bundle verbatim, so the resolver only relays what the target itself signed.  The maintenance tick prunes orphan announcements (peers no longer in the routing table).

**Walker verification (`NetworkPeerQuerier`).** Before inserting any resolved transport into `TransportCache`, the walker checks:
1. `BLAKE3(identity_pubkey) == announcement.node_id` — pubkey ↔ identity binding.
2. Ed25519 signature is valid over the canonical input.
3. `expiry_unix > now()`.
4. `announcement.node_id == requested node_id` (defence-in-depth: even if the resolver attached a valid announcement for the wrong peer, the walker discards it).

A malicious resolver can still **deny** existence (`not_found`) but cannot **redirect** traffic to attacker-controlled infrastructure: that would require forging an Ed25519 signature whose pubkey hashes to the target's `node_id`.

The dispatcher additionally enforces `announcement.node_id == session_peer_id` on `AnnounceTransport` — peers can only announce *their own* node_id, blocking gossip-flood pollution attacks.

**On-disk persistence.** The `transport_announcements: HashMap<node_id, SignedTransportAnnouncement>` map is periodically flushed to a JSON snapshot (default every 120 s + a final flush on clean shutdown).  On restart the snapshot is re-loaded; each entry's signature, pubkey↔node_id binding, and non-expiry are re-verified — failures are silently dropped.

Why JSON instead of the in-memory binary layout: each entry is small (~250 B JSON), the file is operator-grep-able, and the tamper-resistance comes from the signatures (verified on load), not from the on-disk format.  An attacker who edits the file can downgrade availability (drop entries → walker has to re-handshake) but **cannot** inject forged transports — they'd need an Ed25519 keypair whose pubkey hashes to a target's node_id.

Config knobs (`[dht]`):
- `transport_announcements_persist_path: Option<String>` — `None` disables.
- `transport_announcements_persist_interval_secs: u64` — default 120.

The `TransportCache` itself is intentionally **not** persisted — it's a derivation of verified announcements, and the next walk repopulates it on demand.

**Remaining caveats:**
- Каждое `ResolveTransport` дополнительно потребляет токен `dht_quota` (existing per-peer rate-limit) поверх PoW.
- Key rotation invalidates all outstanding announcements signed by the old key — peers re-gossip on next handshake (no graceful migration window yet).

### 5.5 Алгоритм Kademlia

- **K** = 20 (k-bucket size — классическая константа Kademlia)
- **α** = 3 (параллельные запросы за раунд)
- **max_rounds** = 20
- XOR-метрика расстояния: `dist(a, b) = a XOR b`
- Lookup: итеративный, α параллельных FindNode в раунд, пока не улучшается результат или не исчерпаны раунды
- Anti-eclipse: максимум `K/4 = 5` контактов из одного /24 IPv4 (или /48 IPv6) в bucket'е

### 5.6 DeletePayload (multi-algo)

```text
[0..32]           key         [u8; 32]
[32]              algo        u8   (0/1 = Ed25519, 2 = Falcon-512, 3 = Ed25519+Falcon-512, 4 = Ed25519+Falcon-1024)
[33..35]          pk_len      u16 BE
[35..35+pk]       public_key  bytes (зависит от algo: 32 Ed25519, 897 Falcon-512; гибриды несут оба)
[+2]              sig_len     u16 BE
[+slen]           signature   bytes (зависит от algo: 64 Ed25519, ~666 Falcon-512; гибриды несут оба)
```

Валидация:
1. `algo ∈ {0, 1, 2, 3, 4}` (любое значение `SignatureAlgorithm::from_wire_byte`, включая гибриды — U1, чтобы узлы с гибридной идентичностью могли удалять свои записи, а не только владельцы Ed25519/Falcon-512);
2. `crypto::verify_message(algo, public_key, key_bytes, signature) = Ok`;
3. `BLAKE3(public_key) == key` — удалить может только владелец self-owned ключа.

---

## 6. Delivery Plane (Family 3)

### 6.1 DeliveryEnvelope (180 байт header + payload)

```text
[0..32]    recipient_node_id  [u8; 32]
[32..64]   sender_node_id     [u8; 32]
[64..96]   src_app_id         [u8; 32]
[96..128]  app_id             [u8; 32]   (app_id получателя)
[128..132] endpoint_id        u32 BE
[132..164] content_id         [u8; 32]   (BLAKE3 payload)
[164..172] created_at         u64 BE     (Unix-время создания)
[172..176] ttl_secs           u32 BE
[176..180] payload_len        u32 BE
[180..]    payload            bytes
```

**Флаги в заголовке фрейма:**
- `require_ack = true` — запросить подтверждение доставки
- `trace_id` — stream_id фрейма используется как trace correlator

### 6.2 MailboxFetchPayload

```text
[0..32]  recipient_node_id  [u8; 32]
[32..40] after_seq          u64 LE     (получить только seq > after_seq)
```

### 6.3 MailboxAckPayload

```text
[0..32]  recipient_node_id  [u8; 32]
[32..34] count              u16 BE
[34..]   seqs[]             u64 LE × count
```

Подтверждение конкретных (не обязательно последовательных) seq-номеров. Максимальный batch: `MAX_MAILBOX_ACK_BATCH = 256`.

### 6.4 DeliveryStatusPayload

```text
[0..32]  content_id  [u8; 32]
[32]     status      u8  (0=OK, 1=NOT_FOUND, 2=FAILED, 3=DUPLICATE, 4=TTL_EXPIRED)
```

---

## 7. E2E-шифрование

Когда `payload[0] == 0xE2` в `DeliveryEnvelope` — payload зашифрован E2E.

### 7.1 Wire-формат E2eEnvelope (payload[1..])

```text
[0]           version         u8 = 1
[1..3]        kem_ct_len      u16 BE   (1088 для ML-KEM-768)
[3..1091]     kem_ciphertext  [u8; 1088]  (ML-KEM инкапсулированный ключ)
[1091..1103]  nonce           [u8; 12]    (ChaCha20-Poly1305 nonce)
[1103..1107]  ct_len          u32 BE
[1107..]      ciphertext      bytes       (ciphertext + 16-байтный auth tag)
```

### 7.2 Алгоритм шифрования

```
1. (kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_encapsulation_key)
2. key = HKDF-SHA256(
       ikm  = shared_secret,
       info = "ovl1-e2e-v1" || src_id || dst_id
   )[0..32]
3. nonce = random[12]
4. ciphertext = ChaCha20-Poly1305.Seal(
       key    = key,
       nonce  = nonce,
       plain  = plaintext,
       aad    = src_id || dst_id
   )
```

### 7.3 Управление ключами

- Encapsulation key (публичный, 1184 байта) публикуется в DHT при регистрации IPC-эндпоинта
- Decapsulation key (приватный, seed 64 байта) хранится в памяти узла
- TTL кэша ключей: `ipc.e2e_key_ttl_secs` (по умолчанию 3600 сек)

---

## 8. Routing Plane (Family 8)

### 8.1 RouteAnnouncePayload

```text
[0..32]  origin_node_id  [u8; 32]
[32..64] via_node_id     [u8; 32]    (next-hop)
[64]     hop_count       u8
[65]     ttl             u8
[66..70] sequence        u32 BE      (монотонно возрастает у origin)
[70..72] timestamp       u32 BE      (Unix-время объявления, секунды)
```

Ограничения: `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300`, `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30`.

### 8.2 RouteRequestPayload

```text
[0..32]  target_node_id     [u8; 32]
[32..64] requester_node_id  [u8; 32]
[64..68] request_id         u32 BE
[68]     ttl                u8
[69..71] mlkem_pk_len       u16 BE
[71..N]  mlkem_pk           bytes   (ML-KEM pubkey запрашивающего, для E2E ответа)
[N..N+2] ed25519_pk_len     u16 BE
[N+2..]  ed25519_pk         bytes   (pubkey для верификации подписи)
[..]     signature          bytes
```

### 8.3 RouteResponsePayload

```text
[0..32]  target_node_id     [u8; 32]
[32..64] requester_node_id  [u8; 32]
[64..68] request_id         u32 BE
[68..70] transport_count    u16 BE
[70..]   transports[]       (len u16 BE + bytes)  — URI строки
[..]     relay_count        u16 BE
[..]     relays[]           [u8; 32]  — relay node_id'ы
[..]     mlkem_pk_len       u16 BE
[..]     mlkem_pk           bytes
[..]     ed25519_pk_len     u16 BE
[..]     ed25519_pk         bytes
[..]     signature          bytes
```

Лимиты: `MAX_TRANSPORT_ADDRS = 32`, `MAX_RELAY_IDS = 32`.

### 8.4 Proof-of-Work (PoW)

**Хэш-функция:** BLAKE3

```
challenge = random [u8; 32]
difficulty = N  (ведущих нулевых битов)

Решение: найти solution такое, что
BLAKE3(challenge || solution).leading_zero_bits() >= difficulty
```

**PowChallengePayload:**

```text
[0..32]  requester_node_id  [u8; 32]
[32..64] acceptor_node_id   [u8; 32]
[64..96] challenge_nonce    [u8; 32]
[96]     difficulty         u8
[97..161] signature         [u8; 64]   (Ed25519, подпись acceptor)
```

Ограничения: `MAX_POW_DIFFICULTY = 24`, `MAX_CONCURRENT_POW_SOLVERS = 4`.

#### 8.4.1 PoW-gated discovery

Когда у узла-цели сконфигурирован `abuse.pow_min_difficulty > 0`, **`RouteResponse` (с `transports`) откладывается до решения PoW**:

```
Requester ── RouteRequest{target=victim, requester=us} ──► Victim
Requester ◄──────────── PowChallenge{nonce, difficulty} ── Victim   (RouteResponse НЕ отправляется)
                                                  │
                                  Requester решает PoW (BLAKE3)
                                                  │
Requester ── PowResponse{nonce, solution} ────────────────► Victim
Requester ◄── RouteResponse{transports, mlkem_pk, sig} ─── Victim   (deferred — request_id эхо'ится из pow_pending)
Requester ◄── PowAccept{transport} ───────────────────────── Victim   (legacy backward-compat, signals "session bootstrap ОК")
```

**Без PoW (`pow_min_difficulty = 0`):** `RouteResponse` отправляется сразу же при получении `RouteRequest` (legacy поведение).

**Зачем:** без PoW-гейта любой узел мог бесплатно отправить `RouteRequest{target=X}` для произвольного `X` и получить обратно `RouteResponse{transports[X]}` — раскрытие IP/порта по `node_id`. PoW-гейт делает probe-by-id платным.

#### 8.4.2 DiscoveryMode

Дополнительный конфиг `[routing] discovery_mode` (default: `public`):

| Mode | Поведение |
|---|---|
| `public` | Текущее. Если `pow_min_difficulty > 0` — gated через PoW; иначе — immediate `RouteResponse`. |
| `contacts_only` | `RouteRequest` от requester'а вне `peer_pubkeys` (не handshake'ались) **молча дропаются** — ни `PowChallenge`, ни `RouteResponse`. Существование узла остаётся скрыто. |
| `introduction_only` | `RouteResponse.transports` всегда пустой. Requester должен подключаться через один из `relay_ids` (Tor-style introduction approximation без rendezvous). |

---

## 9. IPC-протокол (LocalApp, Family 6)

### 9.1 Протокол соединения

Локальное приложение подключается к IPC-серверу через `ipc.socket_uri` (Unix-сокет `unix:///path` или TCP-loopback `tcp://127.0.0.1:port`).

Каждое сообщение: `u16 BE msg_type` + `u32 BE body_len` + тело.

Версия протокола: `IPC_PROTOCOL_VERSION = 1`.

### 9.2 Последовательность

```
App                              Node
 │── AppHello (v=1) ────────────►│
 │◄─ AppHelloOk ──────────────────│
 │── AppBind (ns, name, ep) ─────►│   Регистрация эндпоинта
 │◄─ AppBindOk (app_id) ──────────│
 │── AppIpcSend / StreamOpen ────►│   Отправка / открытие потока
 │◄─ AppDeliver ──────────────────│   Входящее сообщение
 │── AppUnbind ──────────────────►│   Завершение
```

### 9.3 Типы сообщений LocalApp

Значения `msg_type` — из `LocalAppMsg` в [`proto/family.rs`](../../crates/veil-proto/src/family.rs).

| Тип | `msg_type` | Направление | Описание |
|-----|-----------|-------------|----------|
| AppHello | 0 | App→Node | Версия протокола |
| AppHelloOk | 1 | Node→App | Подтверждение |
| AppHelloErr | 2 | Node→App | Ошибка версии |
| AppBind | 3 | App→Node | Зарегистрировать эндпоинт |
| AppBindOk | 4 | Node→App | app_id присвоен |
| AppBindErr | 5 | Node→App | Ошибка регистрации |
| AppUnbind | 6 | App→Node | Отменить регистрацию |
| AppDeliver | 7 | Node→App | Входящее сообщение |
| AppIpcSend | 8 | App→Node | Отправить сообщение (без подтверждения) |
| AppSendOk | 9 | Node→App | Подтверждение AppIpcSend |
| StreamOpen | 10 | App→Node | Открыть двунаправленный поток |
| StreamOpenOk | 11 | Node→App | Поток открыт (initial_window) |
| StreamOpenErr | 12 | Node→App | Ошибка открытия потока |
| StreamData | 13 | Bidirectional | Данные потока |
| StreamClose | 14 | Bidirectional | Закрыть поток |
| StreamWindow | 15 | Bidirectional | Увеличить send-window |
| StreamRtData | 16 | Bidirectional | Realtime-данные потока |
| AppSendFailed | 17 | Node→App | Доставка не удалась (require_ack) |
| AppRtSend | 18 | App→Node | Outbound realtime-фрейм |
| DeliveryStage | 19 | Node→App | Стадия доставки (Accepted/Stored/Fetched/Delivered/AppAcked) |
| AnycastResolve | 20 | App→Node | Запрос anycast-разрешения сервиса |
| AnycastResult | 21 | Node→App | Ответ anycast-разрешения |

### 9.4 AppBindPayload

```text
[0..2]   namespace_len  u16 BE
[2..N]   namespace      bytes  (UTF-8, напр. "veil.chat")
[N..N+2] name_len       u16 BE
[N+2..M] app_name       bytes  (UTF-8, напр. "main")
[M..M+4] endpoint_id    u32 BE (1..65535)
```

Ответ AppBindOk содержит `app_id [u8; 32]` — см. §1.2 для точной формулы (length-prefixed BLAKE3 `derive_key`).  В ephemeral-режиме (дефолт) используется `ephemeral_app_id` с mix'инг'ом `client_token`; в `bind_named` — стабильная форма `app_id`.

### 9.5 Управление потоками (Stream Flow Control)

- **Send window**: отправитель отслеживает оставшееся окно; блокируется при `window = 0`
- **StreamWindow**: получатель отправляет для увеличения окна отправителя
- **Initial window**: `STREAM_INITIAL_WINDOW` (по умолчанию 256 КиБ)
- **Максимальное окно**: `MAX_STREAM_SEND_WINDOW = 16 МБ`

---

## 10. Mesh Plane (Family 5)

### 10.1 MeshFrame

```text
[0..16]  realm_id   [u8; 16]   (16-байтный realm identifier)
[16..48] src        [u8; 32]   (source node_id)
[48..80] dst        [u8; 32]   (destination node_id; [0u8;32] = broadcast)
[80]     ttl        u8
[81..83] payload_len u16 BE
[83..]   payload    bytes
```

### 10.2 MeshBeaconPayload

```text
[0..32]  node_id      [u8; 32]
[32..48] realm_id     [u8; 16]
[48]     role_flags   u8  (v2: IS_GATEWAY=0x01, IS_CORE=0x02)
[49]     addr_len     u8  (v2: длина veil_addr)
[50..N]  veil_addr bytes  (TCP/TLS URI, напр. "tls://10.0.0.1:9443")
[N]      battery_level u8  (v3: 0=unknown/AC, 1..100=%)
```

### 10.3 MeshAckPayload

```text
[0..16]  frame_id  [u8; 16]
[16]     status    u8  (0=OK, 1=REJECTED, 2=DUPLICATE, 3=NO_ROUTE)
```

---

## 11. Роли узлов

| Роль | Код | DHT | Relay | Mailbox | Gateway | Применение |
|------|-----|-----|-------|---------|---------|------------|
| Leaf | 0x01 | Нет | Нет | Нет | Нет | Мобильные/IoT |
| Core | 0x08 | Да (K=20) | Да | Да | Да | Серверы, VPS |

Legacy-коды 0x02 (Relay), 0x04 (Gateway), 0x10 (CoreRouter) удалены;
от старых пиров такие значения отбрасываются.

**Leaf-узел:**
- Работает через Core-ноду (attachment lease)
- Mailbox хранится на Core-нодах
- Не принимает входящих соединений от произвольных узлов
- Минимальные требования к ресурсам

**Core-узел:**
- Полноценный участник DHT (K=20), relay, forwarding
- Gateway: обслуживает attachment-записи leaf-узлов (отключается через `[gateway] enabled = false`)
- Хранит mailbox для офлайн-получателей
- Обслуживает FindNode/FindValue/Store/Delete
- Рекомендуемая сложность PoW ≥ 24 (дефолт `16`; `MAX_POW_DIFFICULTY = 24` — жёсткий потолок), высокий аптайм (24/7)

---

## 12. Криптография

### 12.1 Алгоритмы подписи

| Алгоритм | Wire-байт `algo` | Pubkey | Privkey | Подпись |
|----------|------------------|--------|---------|---------|
| Ed25519 | 0 / 1 | 32 байта | 32 байта | 64 байта |
| Falcon512 | 2 | 897 байт | 1281 байт | 666 байт |
| Ed25519+Falcon512 (гибрид) | 3 | 929 байт | composite | Ed25519 ‖ Falcon-512 |
| Ed25519+Falcon1024 (гибрид) | 4 | 1825 байт | composite | Ed25519 ‖ Falcon-1024 |

`algo`-байт используется в `IdentityPayload`, `DeletePayload`, mesh-beacon и PEX-подписи.
Session-handshake (`KeyAgreementPayload`) применяет иную конвенцию: 1 = Ed25519, 2 = Falcon512.

### 12.2 Session KDF

```
shared_secret = X25519(ephemeral_private, ephemeral_public_peer)

salt = local_node_id XOR remote_node_id    // commutative — обе стороны одинаково
ikm  = shared_secret
info = "ovl1-session-v1"

[key_a || key_b || session_id] = HKDF-SHA256(salt, ikm, info, len=96)

(tx_key, rx_key) = if local_node_id <= remote_node_id → (key_a, key_b)
                   else                               → (key_b, key_a)
```

Подробности в §3.5. Отдельного `mac_key` нет — целостность покрыта AEAD-tag
(ChaCha20-Poly1305) и handshake-MAC в `SessionConfirm`
(`BLAKE3("ovl1-session-confirm-v1" ‖ shared_secret ‖ small_id ‖ large_id)`).

### 12.3 Frame Encryption

```
ciphertext = ChaCha20-Poly1305.Seal(
    key   = tx_key (для исходящих) / rx_key.open для входящих,
    nonce = 12-byte counter (per-direction, монотонный),
    plain = frame_body,
    aad   = frame_header_bytes (24 байта)
)
```

### 12.4 E2E (Post-Quantum)

```
# Encapsulation (отправитель знает recipient_ek)
(kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_encapsulation_key)

key = HKDF-SHA256(shared_secret, info="ovl1-e2e-v1" || src_id || dst_id)[0..32]
nonce = random[12]
ciphertext = ChaCha20-Poly1305.Seal(key, nonce, plaintext, aad=src_id||dst_id)

# Decapsulation (получатель)
shared_secret = ML-KEM-768.Decaps(kem_ct, decapsulation_key)
key = HKDF-SHA256(shared_secret, info="ovl1-e2e-v1" || src_id || dst_id)[0..32]
plaintext = ChaCha20-Poly1305.Open(key, nonce, ciphertext, aad=src_id||dst_id)
```

### 12.5 PoW

```
challenge: [u8; 32]  (случайный)
difficulty: u8       (количество ведущих нулевых битов)

# Поиск решения:
loop:
    solution = random[32]
    hash = BLAKE3(challenge || solution)
    if hash.leading_zero_bits() >= difficulty:
        break

# Верификация:
assert BLAKE3(challenge || solution).leading_zero_bits() >= difficulty
```

### 12.6 Производные идентификаторы

```
node_id    = BLAKE3(raw_pubkey_bytes)     // 32 байта
app_id     = derive_key("veil.app_id.v1",
                        node_id || ns_len(4) || ns ||
                        name_len(4) || name)  // 32 байта (см. §1.2)
content_id = BLAKE3(payload)              // 32 байта
```

---

## 13. Бюджеты и лимиты

Все константы определены в `crates/veil-proto/src/budget.rs`.

| Константа | Значение | Описание |
|-----------|---------|----------|
| `MAX_FRAME_BODY` | 16 МиБ | Абсолютный потолок тела фрейма (в `proto/codec.rs`); слушатель по умолчанию режет до `DEFAULT_MAX_FRAME_BODY = 1 МиБ` |
| `MAX_NEIGHBOR_TABLE_SIZE` | 256 | Максимум соседей в NeighborTable |
| `MAX_ROUTE_CACHE_SIZE` | 1024 | Записей в RouteCache |
| `MAX_ROUTES_PER_DST` | 4 | Путей на одного получателя |
| `MAX_ROUTES_PER_VIA` | 256 | Маршрутов через одного next-hop |
| `DEFAULT_MAX_QUEUE_DEPTH` | 1000 | Сообщений в очереди на получателя |
| `MAX_MAILBOX_RECIPIENTS` | 4096 | Различных получателей в mailbox |
| `MAX_MAILBOX_ACK_BATCH` | 256 | ACK за одно сообщение |
| `MAX_CONCURRENT_SESSIONS` | 65 536 | Активных сессий |
| `MAX_SESSIONS_PER_IP` | 32 | Сессий от одного IP |
| `MAX_BAN_LIST_SIZE` | 8192 | Записей в BanList |
| `MAX_VIOLATION_TRACKER_SIZE` | 8192 | Записей в ViolationTracker |
| `dht.max_store_entries` (config) | 25 000 | KV-пар в DHT-хранилище (настраивается в `[dht]`, не константа; операторы с большим объёмом RAM поднимают явно) |
| `MAX_DHT_VALUE_BYTES` | 16384 (16 КиБ) | Байт в одном DHT-значении |
| `MAX_PENDING_ACK_ENTRIES` | 1024 | In-flight require_ack сообщений |
| `MAX_DELIVERY_ATTEMPTS` | 3 | Попыток доставки с require_ack |
| `DELIVERY_ACK_TIMEOUT_MS` | 5000 | Таймаут одной попытки (мс) |
| `MAX_TRANSPORT_ADDRS` | 32 | URI в RouteResponse |
| `MAX_RELAY_IDS` | 32 | Relay-узлов в RouteResponse |
| `MAX_GATEWAYS` | 32 | Core-ссылок в AnnounceAttachment |
| `MAX_GATEWAY_ATTACHMENTS` | 4096 | Leaf-узлов на одной Core-ноде |
| `MAX_TRANSPORT_STR_LEN` | 255 | Байт в транспортном URI |
| `MAX_NODES_PER_RESPONSE` | 32 | Узлов в FindNodeResponse |
| `MAX_IPC_ENDPOINTS_PER_CLIENT` | 64 | Эндпоинтов на один IPC-клиент |
| `MAX_FORWARD_SEEN_SET_SIZE` | 100000 | Записей в relay dedup-кэше |
| `FORWARD_SEEN_SET_TTL_SECS` | 60 | TTL записи в dedup-кэше |
| `MAX_BEACON_DEDUP_ENTRIES` | 4096 | Записей в beacon dedup-карте |
| `MAX_TOTAL_STREAMS` | 65536 | Всего открытых потоков |
| `MAX_STREAMS_PER_PEER` | 256 | Потоков на одного пира |
| `MAX_STREAM_SEND_WINDOW` | 16 МБ | Максимальное send-окно потока |
| `REKEY_BYTES_THRESHOLD` | 128 ГиБ | Байт до смены ключей сессии (конфиг: `[session] rekey_bytes_threshold`) |
| `REKEY_TIME_THRESHOLD_SECS` | 2 764 800 (32 дня) | Секунд до смены ключей сессии (конфиг: `[session] rekey_time_threshold_secs`) |
| `MAX_POW_DIFFICULTY` | 24 | Максимальная сложность PoW |
| `MAX_CONCURRENT_POW_SOLVERS` | 4 | Параллельных PoW-решателей |
| `HANDSHAKE_TIMEOUT_SECS` | 10 | Таймаут OVL1-handshake |
| `MAX_CLOCK_SKEW_SECS` | 300 | Допустимое расхождение часов |
| `MAX_ROUTE_ANNOUNCE_AGE_SECS` | 300 | Максимальный возраст RouteAnnounce |
