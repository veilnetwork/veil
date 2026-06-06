# Спецификация протокола OVL1

Версия: **1** (magic `0x4F564C31`), minor = 1.

Это основной справочник по формату OVL1 на проводе — двоичному протоколу, на котором узлы Veil общаются между собой. Документ намеренно точен: имена полей, байтовые смещения и константы здесь совпадают с кодом.

> Для архитектурного обзора — [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).
> Для быстрой справки по формату на проводе — [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

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
- Алгоритм хэширования: BLAKE3, на вход подаются сырые байты публичного ключа (не base64-строка)
- В CLI и конфиге записывается как 64-символьная hex-строка

### 1.2 app_id

```text
app_id = BLAKE3-derive_key(
    context = "veil.app_id.v1",
    ikm     = node_id || ns_len(u32 BE) || app_namespace
                       || name_len(u32 BE) || app_name
)     // 32 байта
```

`app_namespace` и `app_name` — UTF-8-строки произвольного содержания. Их выбирает
разработчик приложения (по соглашению — обратный DNS, например `"com.example.chat"`
+ `"main"`). На проводе каждая ограничена 255 байтами (см. §9.3 `AppBind`).

Префиксы длины и доменный разделитель (строка `context`) **обязательны**. Без них
наивная склейка даёт коллизии: `("foo","bar")` и `("fo","obar")` обе склеиваются в
`"foobar"` и дали бы одинаковый хэш. Формула v1 выше держит каждое поле раздельно,
поэтому результат уникален.

Для IPC-приложений в эфемерном режиме (по умолчанию) формула дополняется
16-байтным `client_token`, который узел выдаёт в `AppHelloOk`:

```text
ephemeral_app_id = BLAKE3-derive_key(
    context = "veil.ephemeral_app_id.v1",
    ikm     = node_id || client_token(16) || ns_len(u32 BE) || app_namespace
                                           || name_len(u32 BE) || app_name
)
```

Так `app_id` становится уникальным для каждого соединения: два процесса на одном
узле, привязывающие одну и ту же пару `(namespace, name)`, всё равно получают разные
адреса. Широко известным сервисам, которым нужен фиксированный адрес, вместо этого
служит стабильная форма выше (через `bind_named`).

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

Это отпечаток тела сообщения. По нему узлы распознают и отбрасывают дубликаты, пока сообщение в пути.

---

## 2. Формат кадров на проводе

Каждое сообщение OVL1 — это *кадр* (frame): фиксированный заголовок в 24 байта, за которым идёт тело. Заголовок говорит, что это за сообщение и какой длины тело; для уровня кадрирования само тело непрозрачно.

### 2.1 Заголовок кадра (FrameHeader)

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

### 2.2 Флаги кадра (flags, биты)

| Бит | Имя | Описание |
|-----|-----|----------|
| 0..1 | priority | 0=RT, 1=Interactive, 2=Bulk, 3=Background |
| 2 | encrypted | Тело зашифровано ChaCha20-Poly1305 |
| 3 | require_ack | Запрос подтверждения доставки |
| 4..15 | reserved | Зарезервировано, должны быть 0 |

### 2.3 Family — семейства протоколов

*Семейство* (Family) объединяет родственные типы сообщений. Байт `Family` в заголовке выбирает группу, а `msg_type` — уже конкретное сообщение внутри неё. Каждое семейство отвечает за свою функциональную область протокола: сессии, обнаружение, доставку и так далее.

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

### 3.1 Рукопожатие (handshake)

Прежде чем обмениваться чем-либо ещё, два узла проводят *рукопожатие* — короткий вступительный диалог, который подтверждает личности и согласует ключи шифрования. Оно асимметрично: ведёт сторона, которая инициирует соединение (инициатор), а другая (отвечающий) отвечает. Обмен идёт в таком порядке:

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

**Обратная совместимость:** старые пиры присылают всего 2 байта, без поля
`discovery_mode`. Декодер заполняет недостающий байт нулём (`0` = Public) — эти пиры
появились до приватности по выбору, так что Public для них — верное значение по
умолчанию. Принимается любая полезная нагрузка длиной `>= 2` байт.

**Что означает `discovery_mode`.** Поле задаёт, насколько узел готов быть найденным
незнакомцами:

- `Public` — пир хочет быть находимым через обход DHT (поиск, прыгающий по распределённой хеш-таблице; см. §5.5); в ответах FIND_NODE от других узлов он будет присутствовать.
- `ContactsOnly` — пир полностью исключается из ответов FIND_NODE; до него можно дотянуться только через прямую сессию с контактом, с которым уже было рукопожатие, либо через заранее заданный список начального подключения (bootstrap).
- `IntroductionOnly` — то же, что `ContactsOnly`, для FIND_NODE, и строже: RouteResponse обязан вырезать `transports[]` (см. §3.6), так что даже успешный поиск маршрута не вернёт адреса.

Устаревшие поля:
- Биты ролей `RELAY (0x02)`, `GATEWAY (0x04)`, `CORE_ROUTER (0x10)` — удалены.
- Флаги возможностей `CAN_MAILBOX=0x02`, `CAN_GATEWAY_LOCAL_MESH=0x04`, `CAN_PARTICIPATE_DHT=0x08`, `CAN_ACCEPT_APP_STREAMS=0x10`, `CAN_STORE=0x20`, `SUPPORTS_TRANSIT=0x40` — их никто никогда не читал, поэтому удалены.
- Формат на проводе со временем ужался: 12 байт (старый) → 2 байта → 3 байта.

### 3.5 SessionKeys (производные ключи)

Сессионные ключи стороны выводят из эфемерного обмена Диффи — Хеллмана на **X25519** —
одноразовой пары ключей, сгенерированной только для этой сессии. Не путайте его с
ключом личности (Ed25519/Falcon-512): тот лишь подписывает `IdentityPayload` и ничего
не шифрует. Вывод устроен так:

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

`tx_key` шифрует исходящие кадры, `rx_key` расшифровывает входящие. Лексикографическое
упорядочивание двух `node_id` гарантирует, что у инициатора и отвечающего `tx_key` и
`rx_key` окажутся поменяны местами: alice.tx равен bob.rx, и наоборот. Именно это и
позволяет каждой стороне расшифровать то, что прислала другая.

Кадры шифруются алгоритмом **ChaCha20-Poly1305** (аутентифицирующий шифр): 32-байтным
ключом `tx_key`/`rx_key`, 12-байтным счётчиком-nonce, своим на каждое направление, а
заголовок кадра идёт как дополнительные аутентифицируемые данные (AAD) — данные,
которые аутентифицируются, но не шифруются.

`session_id` (32 байта) — публичный идентификатор. Он едет в `SessionConfirmPayload`,
а затем служит затравкой соли для последующих перевыработок ключей (rekey, §3.7).

Ключ личности (Ed25519/Falcon-512) в этом выводе **не участвует**. Это сделано
намеренно и даёт прямую секретность (forward secrecy): даже если долгоживущий ключ
личности позже утечёт, прошлые сессии останутся запечатанными.

### 3.6 KeepalivePayload

```text
[0..8]   timestamp_secs  u64 BE
```

Keepalive уходит каждые `session.keepalive_interval_secs` — как знак, что сессия ещё жива. Если ничего не приходит дольше `session.idle_timeout_secs`, сессия считается мёртвой и закрывается.

### 3.7 Rekey (смена ключей)

Долгоживущая сессия время от времени заводит свежие ключи — это *перевыработка ключей*
(rekey), — чтобы ни один ключ не защищал слишком много трафика и не жил слишком долго.
Она срабатывает при переходе любого из порогов: `REKEY_BYTES_THRESHOLD` = 128 ГиБ
переданного трафика или `REKEY_TIME_THRESHOLD_SECS` = 32 дня (2 764 800 с) по часам.
Оба настраиваются в конфиге через `[session] rekey_bytes_threshold` и
`[session] rekey_time_threshold_secs`, и высокочувствительные развёртывания могут
намеренно их понизить.

У постквантового слоя (ML-KEM) есть свои, параллельные часы перевыработки. Его байтовый
бюджет `MLKEM_REKEY_BYTES_THRESHOLD` теперь равен 128 ГиБ — как и `REKEY_BYTES_THRESHOLD`.
Отличается только таймер: `MLKEM_REKEY_TIME_THRESHOLD_SECS` = 1 час. Это короткое окно
держит горизонт прямой секретности сессионного ключа X25519 в ногу со сквозным (E2E)
ключом ML-KEM.

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

Когда узел впервые видит сообщение, он доставляет его локально и пересылает копию **K случайным соседям** с `ttl - 1`. Каждый узел запоминает уже виденные `msg_id`, поэтому дубликаты дальше не расходятся.

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

### 5.1 FindNode (только V2 — V1 удалён)

Исходные сообщения V1 — `FindNode` (слот 0) и `FindNodeResponse` (слот 8), с раскладкой
target+k → `Vec<NodeContact{node_id, transport}>` — убраны. Беда V1 была в том, что один
ответ выдавал *транспорт* (адрес, который набирают) для каждого контакта, и всё это за
один обход (RTT). Так граф маршрутизации утекал оптом, а перечислить всю сеть становилось
до смешного дёшево. Теперь весь трафик FIND_NODE идёт через V2 плюс отдельный шаг
`ResolveTransport` (§5.4.1). Отправитель, который всё ещё шлёт слот 0 или 8, не проходит
`DiscoveryMsg::try_from` и помечается диспетчером как `Violation`.

**`NodeContact`** сохранён лишь как вспомогательная структура на проводе для ветки «не
найдено» у `FindValue`:

```text
[0..32]  node_id       [u8; 32]
[32..34] transport_len u16 BE
[34..N]  transport     bytes  (URI строка)
```

Начиная с **C-06**, эта ветка «не найдено» обнуляет поле транспорта
(`transport_len = 0`, пустой URI). Как и FIND_NODE V2, она возвращает **только
node_id**, а запрашивающая сторона затем по требованию разрешает транспорт каждого
узла через `ResolveTransport` (§5.4.1). Это закрывает ту же массовую утечку графа
маршрутизации и на пути поиска значения. Итеративный (и рекурсивный) обход всё равно
сходится, потому что транспорты разрешаются от прыжка к прыжку, а не встраиваются в
ответ, — регрессионный тест на цепочке из 64 узлов в
`crates/veil-dht/src/iterative.rs` стережёт ровно это.

#### 5.2.1 Фильтр discovery_mode + ограничение вполовину

И V2 FIND_NODE (`handle_find_node_v2`), и запасной путь «не найдено» у `FindValue`
сначала прогоняют возвращаемые контакты через два фильтра — через общий помощник
`ranked_public_contacts`:

1. **Фильтр «только Public».** Пиры, у которых `discovery_mode` не равен `Public` (объявлен в `CapabilitiesPayload.discovery_mode` при рукопожатии), выбрасываются из ответа. Именно это закрывает утечку перечисления для узлов с приватностью по выбору: пир `ContactsOnly` или `IntroductionOnly` не появится в чужих ответах на FIND_NODE, так что сканеры, обходящие DHT, его попросту не увидят.

2. **Ограничение вполовину (half-cap).** Ответ возвращает не более `min(K_requested, K_local, ceil(N_public / 2))` контактов, где `N_public` — сколько Public-пиров лежит в нашей таблице маршрутизации. Ограничение половиной означает, что атакующему, картирующему Public-сеть, придётся послать **минимум вдвое больше запросов FIND_NODE**, чтобы покрыть её целиком. Крайний случай тоже работает: с одним Public-пиром возвращается один, так что связность Kademlia сохраняется.

Аналогичная фильтрация применяется в:

- `handle_find_value::FindValueResponse::Nodes` (closest-nodes fallback)
- `handle_recursive_query::FIND_NODE` (через `find_closest_public_node_ids` helper)

**Не фильтруется** внутренняя маршрутизация — `find_closest_nodes` для выбора следующего прыжка и NeighborOffer. Фильтр там сломал бы маршрутизацию через узлы с приватностью по выбору, работающие как ретрансляторы, а это ровно то, чего мы не хотим.

**Модель угроз.** Цель — устойчивость к сканерам при пассивном перечислении через DHT FIND_NODE. До этой меры сканер одним FIND_NODE вытягивал K транспортов, обходил всё Public-пространство ключей примерно за 10 обходов для /20 и за минуты получал полную карту адресов. Ограничение вполовину вместе с фильтром «только Public» делает такой обход для Public-узлов минимум вдвое медленнее, а для узлов с приватностью по выбору — невозможным.

**Ограничение.** Public-узлы (конфигурация по умолчанию) всё ещё перечислимы, просто порциями не больше половины таблицы за раз. Полное разделение графа маршрутизации и графа адресов — задача на будущее: см. Decoupled transport resolution / hidden services (в планах).

### 5.3 StorePayload

```text
[0..32]  key       [u8; 32]
[32..36] ttl_secs  u32 BE
[36..40] value_len u32 BE
[40..]   value     bytes
```

### 5.4 AnnounceAttachmentPayload

Когда лист привязывается к шлюзу (gateway), он публикует эту запись в DHT, чтобы другие могли узнать, какие Core-узлы его сейчас обслуживают. Точный формат лежит в [`proto/discovery.rs::AnnounceAttachmentPayload`](../../crates/veil-proto/src/discovery.rs):

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

**Протокол на проводе.** `DiscoveryMsg`, слоты 10-14:

| msg_type | Имя | Body |
|---|---|---|
| 10 | `FindNodeV2` | `FindNodeV2Payload` (32 байт target + 1 байт k) |
| 11 | `FindNodeV2Response` | `FindNodeV2Response` (count u8 + node_ids `[u8; 32] × count`) |
| 12 | `ResolveTransport` | `ResolveTransportPayload` (52 байт: 32 node_id + 4 time_bucket BE + 16 pow_nonce) |
| 13 | `ResolveTransportResponse` | `ResolveTransportResponse` — несёт `Option<SignedTransportAnnouncement>` |
| 14 | `AnnounceTransport` | `SignedTransportAnnouncement` — рассылка «отправил и забыл» после рукопожатия |

**FindNodeV2Response** (variable):
```text
[0]                  count       u8  (≤ MAX_NODES_PER_RESPONSE = 32)
[1..1+count*32]      node_ids    [u8; 32] × count
```

Обратите внимание: **транспортных полей здесь нет**, в отличие от удалённой V1 (§5.1). Вызывающая сторона узнаёт только node_id; для каждого узла, до которого ей действительно надо дотянуться, она отдельно вызывает `ResolveTransport` и получает адрес.

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

Резолвер отвечает `not_found` в двух случаях:
- В его таблице маршрутизации нет `Contact` для запрошенного `node_id`.
- Контакт есть, но его `discovery_mode` не равен `Public`. Это фильтр приватности: само существование non-Public-пира через этот RPC не подтверждается. Объединять этот случай с «никогда о нём не слышал» — намеренно: отдельный ответ «знаю, но не скажу» сам стал бы сигналом, которым воспользовался бы атакующий.

**Модель угроз.** Раньше любой FIND_NODE за один обход возвращал K транспортов, так что массовое сканирование картировало сеть за O(N/K) обходов (~10 обходов для 200 Public-узлов в пространстве ключей /20). Обходчик DHT теперь по умолчанию использует V2, где каждый транспорт стоит отдельного RPC, — суммарная стоимость O(N) обходов, сканировать примерно **в 10 раз медленнее**. PoW-затвор и подписанные ответы накручивают ещё: работа CPU на каждое разрешение (~17 мс BLAKE3) и устойчивость к отравлению кэша.

**Состояние.** Типы на проводе, обработчики, кэш в памяти и поток V2 — всё вшито в `NetworkPeerQuerier`. **Защита активна**: исходящие обходы DHT по умолчанию идут по потоку V2 (`FindNodeV2 → node_ids → поиск в кэше → ResolveTransport(id) при промахе`). V1 удалён — слоты на проводе 0/8 отвергаются как `Violation`.

**PoW-затвор.** `ResolveTransportPayload`:

```text
[0..32]    node_id      [u8; 32]   — what to resolve
[32..36]   time_bucket  u32 BE     — `unix_secs() / RESOLVE_POW_BUCKET_SECONDS`
[36..52]   pow_nonce    [u8; 16]   — solution
```

Входной хэш для PoW:

```text
BLAKE3( "epic475.4b/resolve_pow/v1" || requester_node_id[32] ||
         target_node_id[32] || time_bucket_be[4] || pow_nonce[16] )
```

`requester_node_id` на проводе не передаётся. Отвечающий берёт его из контекста сессии — это `peer_id`, который сессия OVL1 уже аутентифицировала. Сервер принимает доказательство, только если выполнены оба условия: `leading_zero_bits(hash) ≥ RESOLVE_POW_DIFFICULTY` и `|time_bucket − now_bucket| ≤ RESOLVE_POW_TIME_WINDOW_BUCKETS`. Значения по умолчанию: `RESOLVE_POW_DIFFICULTY = 16` (медиана ~7 мс на добычу на быстром ядре x86, ~14 мс на слабом ARM), `RESOLVE_POW_BUCKET_SECONDS = 60` и `RESOLVE_POW_TIME_WINDOW_BUCKETS = 1` (окно повтора около 120 с).

Неудачный PoW — плохое решение, устаревший интервал или неверная привязка цели/запросившего — получает тихий `not_found`, а **не** `Violation`. Логика такая: проверка доказательства — это один хэш BLAKE3 (~1 мкс), так что лимит `dht_quota` на каждого пира и без того ограничивает расход CPU, а считать неудачи нарушениями — значит превратить обычный уход часов в путь ложноположительного выселения. А вот старые отправители, у которых полей PoW нет вовсе (полезная нагрузка в 32 байта), не проходят декодирование и *получают* `Violation` от диспетчера.

Итог: стоимость для атакующего растёт с `O(N) обходов` до `O(N) × ~7 мс` CPU на каждый прощупанный `node_id`. Для пространства ключей `/20` (~200 Public-пиров) это около 1,5 с добычи на одном ядре за один полный проход перечисления, и она линейно растёт с размером набора целей — тогда как честный клиент платит её лишь однажды, при промахе кэша.

**Подписанные ответы.** `ResolveTransportResponse.transport: Option<String>` несёт `Option<SignedTransportAnnouncement>`:

```text
[0..32]    node_id          [u8; 32]
[32..64]   identity_pubkey  [u8; 32]   Ed25519 raw pubkey
[64..128]  signature        [u8; 64]   Ed25519 signature
[128..136] expiry_unix      u64 BE
[136..138] transport_len    u16 BE
[138..N]   transport        UTF-8 (≤ MAX_TRANSPORT_URI_LEN = 256)
```

Вход для подписи:

```text
BLAKE3( "epic475.4c/transport_announce/v1" || node_id ||
         expiry_unix_be || transport_len_be || transport_utf8 )
```

Каждый узел при старте выпускает свой набор (действителен 30 дней, по `ANNOUNCEMENT_VALIDITY_SECS`) и **рассылает его через `DiscoveryMsg::AnnounceTransport` (слот 14) при каждом завершённом рукопожатии** — один кадр «отправил и забыл» на сессию, и на входящем, и на исходящем пути. Получатели проверяют его и сохраняют в `transport_announcements: HashMap<node_id, …>` на `KademliaService`. Затем `handle_resolve_transport` отдаёт кэшированный набор дословно, так что резолвер передаёт лишь то, что подписала сама цель. Тик обслуживания вычищает осиротевшие объявления — пиров, выпавших из таблицы маршрутизации.

**Проверка обходчиком (`NetworkPeerQuerier`).** Прежде чем положить любой разрешённый транспорт в `TransportCache`, обходчик проверяет четыре вещи:
1. `BLAKE3(identity_pubkey) == announcement.node_id` — публичный ключ привязан к личности.
2. Подпись Ed25519 верна для канонического входа.
3. `expiry_unix > now()` — набор не просрочен.
4. `announcement.node_id == requested node_id` — защита в глубину: даже если резолвер приложил действительное объявление не для того пира, обходчик его выбрасывает.

Так что вредоносный резолвер может **отрицать** существование пира (`not_found`), но не может **перенаправить** трафик на подконтрольную атакующему инфраструктуру. Перенаправление потребовало бы подделать подпись Ed25519, чей публичный ключ хэшируется в `node_id` цели, — а в этом и весь смысл привязки.

Диспетчер добавляет ещё одну проверку: на `AnnounceTransport` он требует `announcement.node_id == session_peer_id`. Пир может объявлять только *свой* node_id, что блокирует атаки засорения через лавину рассылок.

**Хранение на диске.** Карта `transport_announcements: HashMap<node_id, SignedTransportAnnouncement>` по таймеру сбрасывается в JSON-снимок (по умолчанию каждые 120 с плюс финальный сброс при чистом завершении). При перезапуске снимок загружается заново, и каждая запись перепроверяется — подпись, привязка публичного ключа к node_id и непросроченность, — а любая неудача молча отбрасывается.

Почему JSON, а не двоичная раскладка из памяти? Каждая запись крошечная (~250 Б в JSON), файл остаётся доступным оператору для grep, а устойчивость к подделке даёт не формат файла, а подписи (перепроверяемые при загрузке). Тот, кто отредактирует файл, способен лишь подпортить доступность — выкинуть записи, после чего обходчику придётся заново пожать руки, — но **не** способен подсунуть поддельные транспорты, ведь для этого нужна пара ключей Ed25519, чей публичный ключ хэшируется в node_id цели.

Ручки конфигурации (`[dht]`):
- `transport_announcements_persist_path: Option<String>` — `None` отключает хранение.
- `transport_announcements_persist_interval_secs: u64` — по умолчанию 120.

Сам `TransportCache` намеренно **не** сохраняется. Это всего лишь производное от проверенных объявлений, и следующий обход наполняет его заново по требованию.

**Что остаётся помнить:**
- Каждое `ResolveTransport` вдобавок тратит токен `dht_quota` (существующий лимит частоты на пира) поверх PoW.
- Смена ключа аннулирует все ещё действующие объявления, подписанные старым. Пиры рассылают их заново при следующем рукопожатии — плавного окна миграции пока нет.

### 5.5 Алгоритм Kademlia

- **K** = 20 — размер k-бакета, классическая константа Kademlia.
- **α** = 3 — сколько запросов идёт параллельно в каждом раунде.
- **max_rounds** = 20.
- Метрика расстояния — XOR: `dist(a, b) = a XOR b`.
- Поиск итеративный: α параллельных запросов FindNode в раунд, и так пока результат не перестанет улучшаться или не кончатся раунды.
- Защита от затмения (anti-eclipse): не более `K/4 = 5` контактов из одной подсети /24 IPv4 (или /48 IPv6) на бакет, чтобы одна сеть не забила бакет целиком.

### 5.6 DeletePayload (multi-algo)

```text
[0..32]           key         [u8; 32]
[32]              algo        u8   (0/1 = Ed25519, 2 = Falcon-512, 3 = Ed25519+Falcon-512, 4 = Ed25519+Falcon-1024)
[33..35]          pk_len      u16 BE
[35..35+pk]       public_key  bytes (зависит от algo: 32 Ed25519, 897 Falcon-512; гибриды несут оба)
[+2]              sig_len     u16 BE
[+slen]           signature   bytes (зависит от algo: 64 Ed25519, ~666 Falcon-512; гибриды несут оба)
```

Проверка идёт в три шага:
1. `algo ∈ {0, 1, 2, 3, 4}` — любое значение, которое принимает `SignatureAlgorithm::from_wire_byte`, включая гибриды. Приём гибридов (изменение `U1`) позволяет узлам с гибридной личностью удалять свои записи, а не только владельцам Ed25519/Falcon-512.
2. `crypto::verify_message(algo, public_key, key_bytes, signature) = Ok` — подпись сходится.
3. `BLAKE3(public_key) == key` — ключ принадлежит сам себе, так что удалить его может только владелец.

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

Подтверждает конкретные seq-номера, не обязательно идущие подряд. В одной пачке их не больше `MAX_MAILBOX_ACK_BATCH = 256`.

### 6.4 DeliveryStatusPayload

```text
[0..32]  content_id  [u8; 32]
[32]     status      u8  (0=OK, 1=NOT_FOUND, 2=FAILED, 3=DUPLICATE, 4=TTL_EXPIRED)
```

---

## 7. Сквозное (E2E) шифрование

Сквозное (end-to-end, E2E) шифрование запечатывает сообщение так, что вскрыть его может только конечный получатель — ретрансляторы посередине несут запечатанные байты. Конверт `DeliveryEnvelope`, у которого `payload[0] == 0xE2`, зашифрован сквозным шифрованием; этот первый байт и есть метка.

### 7.1 Формат E2eEnvelope на проводе (payload[1..])

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

- Ключ инкапсуляции (публичный ключ ML-KEM, 1184 байта) публикуется в DHT при регистрации IPC-эндпоинта, чтобы отправители могли его найти.
- Ключ декапсуляции (парный приватный ключ, 64-байтный seed) никогда не покидает память узла.
- Разрешённые ключи кэшируются на `ipc.e2e_key_ttl_secs` (по умолчанию 3600 сек).

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

Если у узла-цели задан `abuse.pow_min_difficulty > 0`, он **придерживает `RouteResponse` (тот, что несёт `transports`), пока запросивший не решит PoW**:

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

**Без PoW (`pow_min_difficulty = 0`):** `RouteResponse` уходит сразу же, как только приходит `RouteRequest`, — прежнее поведение.

**Зачем это нужно.** Без затвора любой узел мог бесплатно выстрелить `RouteRequest{target=X}` для любого `X` на свой вкус и получить обратно `RouteResponse{transports[X]}` — то есть выдать IP и порт X, имея на руках лишь его `node_id`. PoW-затвор делает прощупывание по id настоящей работой.

#### 8.4.2 DiscoveryMode

Дополнительный параметр конфигурации `[routing] discovery_mode` (по умолчанию `public`):

| Режим | Поведение |
|---|---|
| `public` | По умолчанию. При `pow_min_difficulty > 0` ответ закрыт затвором PoW; иначе `RouteResponse` уходит сразу. |
| `contacts_only` | `RouteRequest` от запросившего вне `peer_pubkeys` (с кем мы не пожимали руки) **молча отбрасывается** — ни `PowChallenge`, ни `RouteResponse`. Существование узла остаётся скрыто. |
| `introduction_only` | `RouteResponse.transports` всегда пуст. Запросившему приходится подключаться через один из `relay_ids` — грубое приближение к интродукции в стиле Tor, без рандеву. |

---

## 9. IPC-протокол (LocalApp, Family 6)

### 9.1 Протокол соединения

Так локальное приложение общается с узлом, рядом с которым работает, — это IPC, межпроцессное взаимодействие на одной машине. Приложение подключается к IPC-серверу узла по `ipc.socket_uri`: либо Unix-сокет (`unix:///path`), либо адрес TCP-петли (`tcp://127.0.0.1:port`).

Каждое сообщение на этом сокете кадрируется просто: `u16 BE msg_type`, затем `u32 BE body_len`, затем тело.

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
| StreamWindow | 15 | Bidirectional | Увеличить окно отправки |
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

Ответ AppBindOk несёт `app_id [u8; 32]` — точная формула в §1.2 (BLAKE3 `derive_key` с префиксами длины). В эфемерном режиме (по умолчанию) узел возвращает `ephemeral_app_id`, подмешивая `client_token`; при `bind_named` — вместо этого стабильный `app_id`.

### 9.5 Управление потоком (Stream Flow Control)

Управление потоком не даёт быстрому отправителю захлестнуть медленного получателя. Работает по схеме кредитов (окна):

- **Окно отправки** — отправитель следит, сколько ещё может отправить, и блокируется, как только окно дойдёт до `0`.
- **StreamWindow** — получатель шлёт это сообщение, чтобы выдать ещё кредита и тем расширить окно отправителя.
- **Начальное окно** — `STREAM_INITIAL_WINDOW` (по умолчанию 256 КиБ).
- **Максимальное окно** — `MAX_STREAM_SEND_WINDOW = 16 МБ`.

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

Устаревшие коды 0x02 (Relay), 0x04 (Gateway), 0x10 (CoreRouter) удалены; если старый
пир всё ещё пришлёт такой, он отбрасывается.

**Leaf-узел** — лёгкая роль для телефонов, IoT и всего, что сидит за NAT:
- Дотягивается до сети через Core-узел, по аренде привязки (attachment lease).
- Держит свой mailbox на Core-узлах, а не локально.
- Не принимает входящих соединений от произвольных узлов.
- Требует минимум ресурсов.

**Core-узел** — всегда включённая роль для серверов и VPS:
- Полноценный участник DHT (K=20); ретранслирует и пересылает трафик.
- Работает шлюзом, обслуживая записи привязок leaf-узлов (отключается через `[gateway] enabled = false`).
- Держит mailbox для получателей, которые сейчас офлайн.
- Обслуживает FindNode/FindValue/Store/Delete.
- Должен держать сложность PoW ≥ 24 (по умолчанию `16`, а `MAX_POW_DIFFICULTY = 24` — жёсткий потолок) и работать круглосуточно (24/7).

---

## 12. Криптография

### 12.1 Алгоритмы подписи

| Алгоритм | Wire-байт `algo` | Pubkey | Privkey | Подпись |
|----------|------------------|--------|---------|---------|
| Ed25519 | 0 / 1 | 32 байта | 32 байта | 64 байта |
| Falcon512 | 2 | 897 байт | 1281 байт | 666 байт |
| Ed25519+Falcon512 (гибрид) | 3 | 929 байт | composite | Ed25519 ‖ Falcon-512 |
| Ed25519+Falcon1024 (гибрид) | 4 | 1825 байт | composite | Ed25519 ‖ Falcon-1024 |

Байт `algo` появляется в `IdentityPayload`, `DeletePayload`, mesh-беаконе и PEX-подписях.
Одно исключение: сессионное рукопожатие (`KeyAgreementPayload`) использует иное соглашение — 1 = Ed25519, 2 = Falcon512.

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

Полностью — в §3.5. Отдельного `mac_key` нет: целостность даёт AEAD-тег
(ChaCha20-Poly1305) на каждом кадре плюс handshake-MAC внутри `SessionConfirm`
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

Это жёсткие потолки, которые держат память и CPU узла в рамках под нагрузкой. Все они определены в `crates/veil-proto/src/budget.rs`.

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
| `MAX_PENDING_ACK_ENTRIES` | 1024 | Сообщений require_ack в полёте |
| `MAX_DELIVERY_ATTEMPTS` | 3 | Попыток доставки с require_ack |
| `DELIVERY_ACK_TIMEOUT_MS` | 5000 | Таймаут одной попытки (мс) |
| `MAX_TRANSPORT_ADDRS` | 32 | URI в RouteResponse |
| `MAX_RELAY_IDS` | 32 | Relay-узлов в RouteResponse |
| `MAX_GATEWAYS` | 32 | Core-ссылок в AnnounceAttachment |
| `MAX_GATEWAY_ATTACHMENTS` | 4096 | Leaf-узлов на одной Core-ноде |
| `MAX_TRANSPORT_STR_LEN` | 255 | Байт в транспортном URI |
| `MAX_NODES_PER_RESPONSE` | 32 | Узлов в FindNodeResponse |
| `MAX_IPC_ENDPOINTS_PER_CLIENT` | 64 | Эндпоинтов на один IPC-клиент |
| `MAX_FORWARD_SEEN_SET_SIZE` | 100000 | Записей в кэше дедупликации ретрансляции |
| `FORWARD_SEEN_SET_TTL_SECS` | 60 | TTL записи в кэше дедупликации |
| `MAX_BEACON_DEDUP_ENTRIES` | 4096 | Записей в карте дедупликации беаконов |
| `MAX_TOTAL_STREAMS` | 65536 | Всего открытых потоков |
| `MAX_STREAMS_PER_PEER` | 256 | Потоков на одного пира |
| `MAX_STREAM_SEND_WINDOW` | 16 МБ | Максимальное окно отправки потока |
| `REKEY_BYTES_THRESHOLD` | 128 ГиБ | Байт до смены ключей сессии (конфиг: `[session] rekey_bytes_threshold`) |
| `REKEY_TIME_THRESHOLD_SECS` | 2 764 800 (32 дня) | Секунд до смены ключей сессии (конфиг: `[session] rekey_time_threshold_secs`) |
| `MAX_POW_DIFFICULTY` | 24 | Максимальная сложность PoW |
| `MAX_CONCURRENT_POW_SOLVERS` | 4 | Параллельных PoW-решателей |
| `HANDSHAKE_TIMEOUT_SECS` | 10 | Таймаут OVL1-handshake |
| `MAX_CLOCK_SKEW_SECS` | 300 | Допустимое расхождение часов |
| `MAX_ROUTE_ANNOUNCE_AGE_SECS` | 300 | Максимальный возраст RouteAnnounce |
