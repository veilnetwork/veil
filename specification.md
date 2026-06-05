Ниже — цельная спецификация и дорожная карта до **функциональной иерархической hybrid-сети**, развиваемой **в репозитории `veilnetwork/veil`**, а не в новом проекте.

Сразу важная оговорка:

> **“Запускать на триллионах устройств”** — это не то, что можно честно доказать лабораторно на ранних этапах. Реалистичная цель спецификации — построить архитектуру, которая **не упирается концептуально** в 10⁶–10⁹ и не содержит решений, которые гарантированно ломаются при дальнейшем росте. Практическая проверка пойдёт через devnet → cluster → geo-distributed pilot → large simulation.

---

# 1. Базовые инварианты

Эти вещи фиксируются сразу и не пересматриваются без очень веской причины.

## 1.1 Identity

```text
node_id = BLAKE3(public_key) // 32 bytes
```

Это уже соответствует текущему `veil`, где `NodeId::from_public_key()` считает 32-байтный BLAKE3 от публичного ключа. 

## 1.2 Node addressing

Если участники узнают друг друга по публичным ключам, то:

```text
node_addr := node_id
```

Отдельного “магического” адреса узла не нужно.

* `node_id` — глобальный стабильный адрес узла
* текущая достижимость — отдельные attach/gateway/mailbox records
* transport endpoint — отдельный runtime state, не часть identity

## 1.3 Application addressing

```text
app_id = BLAKE3-derive_key(
    "veil.app_id.v1",
    node_id || ns_len(u32 BE) || app_namespace || name_len(u32 BE) || app_name
)
```

Length-prefix'ы обязательны (Epic 452): без них `("foo","bar")` и `("fo","obar")`
давали бы одинаковый digest. Domain separator `"veil.app_id.v1"` исключает
коллизии с другими BLAKE3-хешами протокола.

Адрес конечной точки приложения:

```text
AppAddress {
  node_id: [u8; 32],
  app_id: [u8; 32],
  endpoint_id: u32,
}
```

## 1.4 Content addressing

```text
content_id = BLAKE3(content_bytes)
```

или с domain separation:

```text
content_id = BLAKE3(app_id || content_type || payload)
```

## 1.5 Архитектурное разделение

Сеть обязана быть разделена на роли:

* `leaf` — мобильный/слабый узел
* `core` — полноправный участник сети

И на плоскости:

* transport plane
* session/security plane
* veil control plane
* discovery plane
* delivery plane
* local mesh plane
* application plane

---

# 2. Целевая архитектура

## 2.1 Роли узлов

### Leaf

Слабый/мобильный/периодически оффлайновый узел.

Свойства:

* может не иметь публичной достижимости
* не участвует в DHT
* не хранит чужие записи
* работает через Core-ноды и mailbox

### Core

Полноправный участник сети. Все Core-ноды равноправны.

Свойства:

* участвует в DHT (K=20), relay/forwarding
* gateway: публикует attachment records leaf-узлов (по умолчанию вкл, отключается через конфиг)
* хранит mailbox shards для офлайн-получателей
* NAT relay для leaf-узлов за NAT
* mesh bridge (опционально, по конфигу)
* PoW ≥ 24 бит, высокий uptime

---

# 3. Что есть сейчас в `veil`

Это важно для плана внедрения.

Сейчас проект уже содержит:

* workspace с `veilcore`
* transport registry и backends: `tcp`, `tls`, `quic`, `websocket`, `unix`, `socks` 
* runtime узла с listeners, outbound peers, sessions, metrics, admin
* JSON handshake с `public_key`, `nonce`, `node_id` 
* config model с `NodeId`, `PeerId`, `ListenId`, transport/global/identity settings
* crypto и identity PoW policy

### Текущее ограничение

Сейчас это **foundation runtime**, а не полноценно layered veil-network stack.
Именно поэтому дорожная карта ниже начинается с разделения planes и нового протокола.

---

# 4. Спецификация протокола

## 4.1 Общий wire format

Текущий JSON-handshake должен быть заменён на бинарный veil protocol; нынешний handshake полезен только как временный bootstrap/legacy режим. 

### Базовый frame header

```text
FrameHeader {
  magic: [u8; 4]      // "OVL1"
  version: u8         // 1
  family: u8          // session/control/discovery/delivery/app
  msg_type: u16
  flags: u16
  header_len: u16
  body_len: u32
  stream_id: u32
  request_id: u32
}
```

Свойства:

* фиксированный заголовок
* компактный бинарный парсинг
* пригодно для TCP/QUIC/WS
* легко multiplex-ить
* удобно для bounded resource usage

### Расширения

После header — TLV extension block.

---

## 4.2 Families сообщений

### Session family

* `HELLO`
* `IDENTITY`
* `CAPABILITIES`
* `KEY_AGREEMENT`
* `SESSION_CONFIRM`
* `ATTACH`
* `DETACH`
* `KEEPALIVE`

### Control family

* `PING`
* `PONG`
* `NEIGHBOR_OFFER`
* `ROUTE_PROBE`
* `ROUTE_REPLY`
* `ERROR`

### Discovery family

* `FIND_NODE`
* `FIND_VALUE`
* `STORE`
* `DELETE`
* `ANNOUNCE_ATTACHMENT`
* `GET_ATTACHMENT`
* `GET_MAILBOX_SET`
* `GET_APP_ENDPOINT`

### Delivery family

* `MAILBOX_PUT`
* `MAILBOX_FETCH`
* `MAILBOX_ACK`
* `FORWARD`
* `DELIVERY_STATUS`

### App family

* `APP_OPEN`
* `APP_DATA`
* `APP_CLOSE`
* `APP_SEND`
* `APP_RECEIPT`

---

## 4.3 Session protocol

### Этапы

1. `HELLO`
2. `IDENTITY`
3. `CAPABILITIES`
4. `KEY_AGREEMENT`
5. `SESSION_CONFIRM`
6. `ATTACH`

### Цель

Разделить:

* identity
* secure session
* role negotiation
* attachment

### `IDENTITY`

Минимум:

```text
IdentityFrame {
  algo: u8
  public_key_len: u16
  public_key: bytes
  node_id: [u8; 32]
  nonce_len: u8
  nonce: bytes
}
```

### `CAPABILITIES`

```text
CapabilitiesFrame {
  roles_supported: bitset
  transports_supported: bitset
  can_store: bool
  can_relay: bool
  can_mailbox: bool
  can_gateway_local_mesh: bool
  can_participate_dht: bool
  can_accept_app_streams: bool
  max_frame_size: u32
  max_streams: u16
}
```

### `ATTACH`

```text
AttachFrame {
  role: u8
  realm_id: u32
  attach_epoch: u32
  mailbox_preference_count: u8
  gateway_preference_count: u8
  flags: u16
}
```

---

# 5. Модель данных

## 5.1 Attachment record

```text
AttachmentRecord {
  node_id: [u8; 32]
  role: u8
  realm_id: u32
  epoch: u32
  gateway_count: u8
  mailbox_count: u8
  gateways: GatewayRef[]
  mailboxes: MailboxRef[]
  expires_at: u64
  seq_no: u64
  signature: bytes
}
```

Это не identity и не transport endpoint.
Это **текущее состояние достижимости**.

## 5.2 GatewayRef

```text
GatewayRef {
  gateway_node_id: [u8; 32]
  priority: u16
  weight: u16
  flags: u16
}
```

## 5.3 MailboxRef

```text
MailboxRef {
  mailbox_node_id: [u8; 32]
  shard_id: u32
  priority: u16
  flags: u16
}
```

## 5.4 App endpoint record

```text
AppEndpointRecord {
  node_id: [u8; 32]
  app_id: [u8; 32]
  endpoint_id: u32
  epoch: u32
  flags: u16
  capabilities: u32
  expires_at: u64
  signature: bytes
}
```

## 5.5 DHT value envelope

```text
DhtValue {
  key: [u8; 32]
  kind: u8
  epoch: u32
  ttl_secs: u32
  seq_no: u64
  body_len: u32
  body: bytes
  signature_len: u16
  signature: bytes
}
```

---

# 6. Discovery / DHT

## 6.1 Общий принцип

DHT участвует только в:

* `core`
* части `gateway`

`leaf` не участвует в ownership.

## 6.2 Что хранится в DHT

* attachment records
* mailbox set records
* gateway set records
* app endpoint records
* capability descriptors

## 6.3 Что не хранится в DHT

* прямые live transport endpoints leaf-узлов
* горячий presence
* transient route cache
* внутренние local mesh links

## 6.4 DHT метрика

Обычный XOR-space.

```text
distance(a, b) = a XOR b
```

## 6.5 Идентификаторы

* node routing key = `node_id`
* attachment key = `BLAKE3("attach" || node_id)`
* mailbox key = `BLAKE3("mailbox" || node_id || epoch)`
* app endpoint key = `BLAKE3("app" || node_id || app_id || endpoint_id)`

## 6.6 Масштабный принцип

Триллион устройств не означает триллион DHT-owners online.
Большая часть должна быть `leaf`, attach-only, mailbox-backed.

---

# 7. Delivery plane

Это строится **раньше DHT**, потому что доставляемость важнее красивого lookup.

## 7.1 Режимы доставки

### Live forward

Если адресат reachable сейчас:

* sender → gateway/mailbox/core → target

### Store-and-forward

Если адресат offline/intermittent:

* sender пишет в mailbox set
* recipient later fetches backlog

### Local mesh delivery

Если адресат в локальном realm:

* gateway/relay доставляет по local mesh plane

## 7.2 Mailbox semantics

### `MAILBOX_PUT`

Положить зашифрованный envelope.

### `MAILBOX_FETCH`

Забрать сообщения после seq/offset.

### `MAILBOX_ACK`

Подтвердить приём и удалить backlog, если политика позволяет.

## 7.3 Delivery envelope

```text
DeliveryEnvelope {
  recipient_node_id: [u8; 32]
  app_id: [u8; 32]
  endpoint_id: u32
  content_id: [u8; 32]
  created_at: u64
  ttl_secs: u32
  payload_len: u32
  payload: bytes
}
```

---

# 8. Local mesh plane

## 8.1 Назначение

Для:

* Bluetooth
* Wi-Fi Direct
* local ad-hoc/LAN
* other constrained links

## 8.2 Принцип

Local mesh plane не обязан знать глобальную DHT.

Он должен уметь:

* обнаруживать локальных соседей
* forward-ить пакеты по realm
* прикреплять leaf к gateway
* буферизовать low-power узлы через friend/gateway semantics

## 8.3 Абстракции

```text
LocalLink
MeshNeighborProvider
MeshForwarder
GatewayBridge
RealmMembership
```

Сначала это реализуется через simulation/in-memory/UDP, а потом подключаются реальные BLE/Wi-Fi backends.

---

# 9. Vivaldi / latency optimization

## 9.1 Не использовать как ID

Vivaldi не используется как:

* `node_id`
* DHT placement key
* ownership-space identifier

## 9.2 Использовать как hint

Только для:

* выбора ближайшего gateway
* выбора порядка обращения к mailbox replicas
* ранжирования соседей/relays
* route scoring

## 9.3 Смысл

Это только performance optimization. Не trust anchor.

---

# 10. Технологический стек

## 10.1 Ядро

* Rust
* Tokio

## 10.2 Транспорт

Порядок приоритета:

1. QUIC
2. TLS/TCP
3. WS/WSS
4. Unix
5. SOCKS-wrapper
6. BLE/Wi-Fi-local through mesh plane

Текущий transport layer уже даёт хороший фундамент для этого. 

## 10.3 Формат данных

* свой бинарный framing
* TLV / varint
* без JSON в hot path

## 10.4 Криптография

* существующая identity-model остаётся
* session-layer выносится отдельно
* Ed25519 default
* Falcon512 optional, как уже подготовлено в config model 

---

# 11. Эпики и задачи

Ниже — дорога до работающей сети.

---

## Эпик 0. Архитектурная заморозка основы

### Цель

Зафиксировать неизменяемые сущности и vocabulary.

### Задачи

* зафиксировать `node_id = BLAKE3(pubkey)`
* зафиксировать `node_addr == node_id`
* зафиксировать `app_id` формулу
* утвердить роли `leaf/core`
* утвердить plane model
* утвердить что Vivaldi не участвует в ownership

### Результат

Документ `docs/architecture/foundation.md`

### Done when

* все ключевые термины и идентификаторы описаны
* больше нет спорных трактовок `node_addr`

---

## Эпик 1. Новый бинарный протокол

### Цель

Уйти от JSON-handshake к компактному binary wire protocol.

### Задачи

* добавить `proto/header.rs`
* добавить `proto/family.rs`
* добавить `proto/codec.rs`
* добавить TLV extension support
* добавить bounded decoding
* добавить frame fuzzer/property tests

### Результат

Новый пакетный протокол `OVL1`

### Done when

* два узла обмениваются бинарными `HELLO/IDENTITY`
* JSON-handshake остаётся только как legacy-mode
* все новые integration tests используют новый codec

---

## Эпик 2. Session plane

### Цель

Разделить identity, session security и attach negotiation.

### Задачи

* реализовать `HELLO`
* реализовать `IDENTITY`
* реализовать `CAPABILITIES`
* реализовать `KEY_AGREEMENT`
* реализовать `SESSION_CONFIRM`
* реализовать `ATTACH`
* сделать session manager отдельно от node runtime

### Результат

Узлы устанавливают сессии с role/capability negotiation

### Done when

* есть machine-readable session FSM
* runtime создаёт session objects, а не просто “raw connected streams”
* роли и способности доступны после handshake

---

## Эпик 3. Runtime decomposition

### Цель

Разрезать текущий `NodeRuntime` на сервисы.

### Задачи

* вынести `TransportRuntime`
* вынести `SessionRegistry`
* вынести `MetricsHttp`
* вынести `OutboundConnector`
* вынести `ListenerSupervisor`
* сделать orchestration shell

### Результат

Нет монолитного runtime-файла с логикой всех planes

### Done when

* `runtime.rs` становится тонким оркестратором
* listeners/peers/sessions обслуживаются отдельными subsystems

---

## Эпик 4. Role model

### Цель

Ввести role-based behaviour.

### Задачи

* добавить `NodeRole`
* расширить config
* ввести role-based capability set
* запретить `leaf` участвовать в DHT ownership
* разрешить `gateway` bridge behaviour
* добавить tests per role

### Результат

Один и тот же бинарник умеет работать в ролях leaf/core

### Done when

* роль влияет на доступные протоколы и storage behaviour
* в CLI/runtime видна активная роль узла

---

## Эпик 5. Delivery-first core

### Цель

Сделать сеть полезной до DHT.

### Задачи

* реализовать `MAILBOX_PUT`
* реализовать `MAILBOX_FETCH`
* реализовать `MAILBOX_ACK`
* реализовать `FORWARD`
* реализовать backlog queue
* реализовать TTL/cleanup
* добавить end-to-end tests sender → mailbox → recipient

### Результат

Сообщения доставляются online и offline через mailbox

### Done when

* leaf может получать backlog после reconnect
* gateway/core может выступать mailbox
* есть delivery receipts статуса transport/delivery

---

## Эпик 6. App addressing and demux

### Цель

Адресовать не только узлы, но и приложения/endpoint-ы.

### Задачи

* реализовать `app_id`
* реализовать `AppAddress`
* добавить app router
* добавить endpoint registry
* реализовать `APP_OPEN/APP_DATA/APP_CLOSE`
* сделать минимальное demo app API

### Результат

На узле можно принимать сообщения разным приложениям

### Done when

* приложение регистрирует `(app_id, endpoint_id)`
* доставка идёт до конкретного app endpoint

---

## Эпик 7. Gateway and leaf attachment

### Цель

Сделать жизнеспособную hybrid-сеть без DHT.

### Задачи

* gateway attachment table
* leaf attach/detach/reattach
* friend-like buffering для low-power leaf
* heartbeat/lease
* local reachability abstraction
* tests: leaf behind gateway still receives messages

### Результат

Leaf за gateway полноценно работает без публичной достижимости

### Done when

* leaf attach survives reconnect
* gateway хранит attachment leases
* delivery через gateway работает стабильно

---

## Эпик 8. Static discovery bootstrap

### Цель

Перед DHT дать ограниченно работающий discovery-plane.

### Задачи

* static core directory
* bootstrap set config
* attachment lookup через static core map
* mailbox lookup без Kademlia
* app endpoint lookup без Kademlia

### Результат

Небольшая сеть уже живёт без полноценного DHT

### Done when

* 10–100 core/gateway nodes can resolve targets through bootstrap directory
* delivery работает на нескольких доменах

---

## Эпик 9. Core-only Kademlia

### Цель

Добавить стабильный discovery plane.

### Задачи

* bucket table
* `FIND_NODE`
* `FIND_VALUE`
* `STORE`
* `DELETE`
* replication policy
* TTL/republish
* attachment keying
* mailbox keying
* app endpoint keying
* anti-sybil admission hooks using identity policy/PoW base

### Результат

Core nodes держат DHT, leaf туда не лезут

### Done when

* attachment/mailbox/app lookup работает через Kademlia
* recovery после выпадения части core узлов не ломает discovery
* DHT integration tests проходят в churn simulation

---

## Эпик 10. Local mesh abstraction

### Цель

Ввести local mesh plane без привязки к BLE с первого дня.

### Задачи

* `LocalLink` trait
* `MeshNeighborProvider`
* `MeshForwarder`
* `GatewayBridge`
* simulated local realm backend
* UDP realm backend
* realm-scoped addressing

### Результат

Можно тестировать mesh behaviour без BLE hardware

### Done when

* в testnet есть локальные сегменты за gateway
* relay chain внутри realm работает

---

## Эпик 11. Real local transports

### Цель

Подключить настоящие local links.

### Задачи

* BLE transport backend
* Wi-Fi Direct / LAN peer discovery backend
* local advertisement beacons
* duty-cycle aware forwarding
* low-power leaf policy

### Результат

Реальные mesh-сегменты подключаются к veil

### Done when

* leaf без интернета, но с BLE/Wi-Fi-hop path, получает delivery через gateway chain
* есть smoke tests на реальном железе

---

## Эпик 12. Routing optimization

### Цель

Повысить производительность, не меняя identity/ownership model.

### Задачи

* RTT probes
* Vivaldi-like optional coordinate subsystem
* neighbor scoring
* preferred gateway ranking
* replica ordering
* route cache
* path diversity

### Результат

Сеть быстрее, но архитектурно остаётся той же

### Done when

* median delivery latency падает на benchmark scenarios
* optimization can be switched off without loss of correctness

---

## Эпик 13. Storage and compactness hardening

### Цель

Добиться компактных записей и bounded resource usage.

### Задачи

* fixed-size structs where possible
* varint/TLV audit
* max frame size enforcement
* zero-copy decode where safe
* compact record formats
* benchmark memory footprint
* benchmark bandwidth overhead

### Результат

Сеть не распухает на control traffic

### Done when

* protocol budget documented
* per-frame and per-record size budgets enforced in tests

---

## Эпик 14. Abuse resistance

### Цель

Сделать сеть живучей под hostile conditions.

### Задачи

* per-role rate limits
* mailbox quotas
* attachment quotas
* identity PoW integration
* replay windows
* invalid frame bans
* reputation hooks
* admission policy for DHT participants

### Результат

Сеть переживает базовые spam/sybil/resource exhaustion scenarios

### Done when

* abuse tests показывают bounded degradation
* leaf/gateway/core policies различаются

---

## Эпик 15. Observability and operations

### Цель

Сделать сеть управляемой.

### Задачи

* metrics per plane
* admin API per service
* session tracing
* DHT health metrics
* mailbox backlog metrics
* realm/gateway metrics
* structured logs
* debug dump of role state

### Результат

Сеть можно дебажить не вслепую

### Done when

* core/gateway/leaf видны в metrics/admin
* можно быстро понять, где сломался delivery/discovery/mesh

---

## Эпик 16. Compatibility and migration

### Цель

Довести `veil` от текущего состояния до нового без полной остановки разработки.

### Задачи

* legacy handshake compatibility feature flag
* migration path old runtime → new session/runtime
* config upgrader
* docs rewrite
* deprecation plan for old admin/state assumptions

### Результат

Переход контролируемый, а не “big bang rewrite”

### Done when

* старые integration tests либо удалены сознательно, либо завернуты в legacy mode
* новый stack является default

---

## Эпик 17. Functional network milestones

### Цель

Вывести сеть в реально запускаемое состояние.

### Этапы

1. 2-node binary protocol bringup
2. leaf ↔ gateway ↔ core messaging
3. mailbox offline delivery
4. app addressing
5. static discovery network
6. core-only DHT
7. simulated local mesh
8. real local transport
9. geo-distributed pilot
10. large-scale simulation

### Результат

Не “куча модулей”, а живая сеть

### Done when

* есть devnet scripts
* есть pilot deployment guide
* есть benchmark harness

---

# 12. Порядок реализации

Самый рациональный порядок:

1. Эпик 0
2. Эпик 1
3. Эпик 2
4. Эпик 3
5. Эпик 4
6. Эпик 5
7. Эпик 6
8. Эпик 7
9. Эпик 8
10. Эпик 9
11. Эпик 10
12. Эпик 11
13. Эпик 12
14. Эпик 13
15. Эпик 14
16. Эпик 15
17. Эпик 16
18. Эпик 17

Это путь “delivery-first, discovery-later, optimization-last”.

---

# 13. Что можно ломать по дороге

Можно временно ломать:

* текущий JSON-handshake
* текущую модель configured peers as the main networking model
* часть старого runtime/admin assumptions
* старые debug-only session semantics

Нельзя ломать без очень веской причины:

* `node_id = BLAKE3(pubkey)` 
* transport abstraction layer as foundation 
* role/plane separation после утверждения
* принцип “Vivaldi не участвует в ownership”

---

# 14. Что означает “дорога до триллиона устройств”

Это не значит, что на одном этапе будет доказан 10¹²-node deployment.

Это значит, что:

* `leaf` составляют подавляющее большинство
* `core` — малая стабильная подсистема
* `gateway` и `mailbox` отделяют достижимость от identity
* DHT хранит только необходимые control/discovery records
* контрольный трафик не зависит линейно от общего числа устройств
* local mesh не затягивается в global DHT ownership

Именно так архитектура остаётся принципиально масштабируемой.

---

# 15. Итог

Для `veilnetwork/veil` правильная спецификация выглядит так:

> **стабильный `node_id = BLAKE3(pubkey)`, `node_addr == node_id`, собственный бинарный veil protocol, роли `leaf/core`, delivery-first architecture, core-only DHT, local mesh как отдельный plane, Vivaldi только как optimization hint.**

Это даёт:

* работающую mixed internet + mesh сеть,
* offline delivery,
* app addressing,
* ремонтопригодную архитектуру,
* путь к очень большому масштабу без концептуально самоубийственных решений.

Следующий самый полезный шаг — перевести это в **RFC-style документ для репозитория**: `docs/rfcs/0001-hybrid-veil-architecture.md` с exact packet formats и milestone checklist.
