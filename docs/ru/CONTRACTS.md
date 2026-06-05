# Сетевые контракты OVL1

Этот документ описывает, что veil-сеть **гарантирует** приложениям, что
она явно **не гарантирует** и как **версионируется** протокол. Это
авторитетный референс для разработчиков приложений поверх OVL1.

---

## 1. Доставка

**Протокол:** plane `IPC_SEND` / `DELIVERY_FORWARD`.

### Что гарантируется

| Гарантия | Условие |
|----------|---------|
| **Best-effort delivery** | Всегда — сеть делает попытку single-path forwarding'а; повторных передач на сетевом уровне нет. |
| **At-least-once ACK** | Когда sender ставит `IPC_SEND_FLAG_REQUIRE_ACK`; узел ретрансмитит, пока не получит `DELIVERY_ACK` из destination mailbox'а. |
| **Подавление дубликатов на destination'е** | Destination-узел дедуплицирует по `content_id` (32-байтный идентификатор); приложения всё равно могут увидеть дубликаты, если обходят mailbox-слой. |

### Что НЕ гарантируется

- **Порядок** между независимыми датаграммами: два сообщения, отправленные одному peer'у, могут прийти не по порядку.
- **Доставка** без `IPC_SEND_FLAG_REQUIRE_ACK`: кадр может быть молча отброшен на любом hop'е.
- **Своевременность**: SLA по latency нет; congestion, изменения маршрутов или offline-peer'ы могут задержать доставку до `ttl_secs`.

### Ключевые константы

- `MAX_CLOCK_SKEW_SECS = 300` — `created_at` envelope'а не может быть больше чем на 5 минут в будущем.
- `MAX_RELAY_HOPS = 16` — envelope'ы, превысившие этот счётчик hop'ов, отбрасываются relay-узлами.

---

## 2. Streams

**Протокол:** plane `APP_OPEN` / `APP_DATA` / `APP_CLOSE` (application-слой OVL1).

### Что гарантируется

| Гарантия | Условие |
|----------|---------|
| **Ordered delivery** | Все байты внутри одного `stream_id` приходят в том порядке, в котором были отправлены. |
| **Reliable delivery** | Underlying session-транспорт ретрансмитит потерянные кадры; stream-слой не добавляет независимой retransmit-логики. |
| **Half-close-семантика** | Любая сторона может послать `APP_CLOSE`, чтобы сигнализировать, что больше данных слать не будет; другая сторона может продолжать слать, пока тоже не закроет. |
| **Flow control** | Sender уважает `initial_window`, анонсированный в `APP_RECEIPT`; receiver обязан выпускать window updates, чтобы не было stalling'а. |

### Что НЕ гарантируется

- **Cross-stream ordering**: байты на `stream_id = 1` и `stream_id = 2` могут произвольно перемежаться.
- **Доставка при разрыве session'а**: если underlying session терминируется, открытые stream'ы молча abort'ятся (доставка `APP_CLOSE` до peer'а не гарантируется).

### Ключевые константы

- `MAX_STREAM_SEND_WINDOW = 16 MiB` — максимум in-flight байт на stream; sender'ы, превысившие это, получают backpressure.
- `MAX_STREAM_INITIAL_WINDOW = 16 MiB` — анонсированный пиром `initial_window` обрезается до этого значения (и при открытии stream, и при `window_update`), чтобы пир не мог анонсировать завышенное окно и заставить локальную сторону буферизовать неограниченно (U3).

---

## 3. Безопасность

**Протокол:** session handshake + E2E encryption layer.

### Identity

- **Node identity**: `node_id = BLAKE3(public_key_bytes)`. Signing key — Ed25519 **или** Falcon-512 (per-node). Session handshake (`SESS_IDENTITY` / `SESS_CONFIRM`) доказывает знание private key; relay не может имперсонировать peer'а без его private key.
- **Session-конфиденциальность**: после handshake'а все session-кадры зашифрованы общим ключом, выведенным из X25519-ephemeral-DH (HKDF-SHA256); relay-узлы не могут прочитать содержимое кадров.

### End-to-end шифрование

- **Непрозрачность content'а**: application-payload зашифрован E2E (`ChaCha20-Poly1305`) между sender'ом и recipient-узлом; relay-узлы видят только `dst_node_id` и `content_id`.
- **Аутентификация sender'а**: по умолчанию `node_id` sender'а аутентифицирован внутри ciphertext'а; верифицировать может только recipient.
- **Replay protection**: destination-узел держит 32-секундное replay-окно по `content_id`; peer, ретранслирующий вне этого окна, триггерит ban.

### Что НЕ гарантируется

- **Forward secrecy на уровне датаграммы**: текущий E2E-слой использует long-term recipient pubkey; session-ключи дают forward secrecy только на transport-уровне.
- **Анонимность от recipient'а**: recipient всегда узнаёт `node_id` sender'а из аутентифицированного ciphertext'а (если только не выставлен `IPC_SEND_FLAG_ANONYMOUS` — см. §4).

---

## 4. Privacy

**Протокол:** `IPC_SEND_FLAG_ANONYMOUS` + meta-E2E encryption.

### Anonymous send

Когда клиент выставляет `IPC_SEND_FLAG_ANONYMOUS` в `IPC_SEND`:

1. Узел вызывает `meta_encrypt` вместо стандартного `encrypt`; внешний `DeliveryEnvelope` несёт `sender_node_id = [0u8; 32]`.
2. **Relay-узлы** видят только `dst_node_id`; identity sender'а им не видна.
3. **Recipient** расшифровывает meta-E2E ciphertext и восстанавливает ephemeral-ключ sender'а, но **не** стабильный `node_id` (если только приложение само не вложит его в payload).

### Что НЕ гарантируется

- **Анонимность sender'а от recipient'а**: текущая meta-E2E схема использует ephemeral key pair на каждое сообщение; recipient не может связать два anonymous-сообщения с одним и тем же sender'ом, но sender не скрыт от traffic analysis, если приложение шлёт идентифицирующий контент.
- **Network-level анонимность**: relay-узлы форвардят кадры по `dst_node_id`; traffic-analysis adversary, наблюдающий несколько hop'ов, может скоррелировать sender'а и recipient'а.
- **Анонимность proxy**: SOCKS5 exit-proxy (`IPC_PROXY_*`) знает originating-узел, запросивший соединение.

---

## 5. DHT

**Протокол:** Kademlia-based распределённая хэш-таблица поверх discovery-plane.

### Что гарантируется

| Гарантия | Условие |
|----------|---------|
| **k-replication** | Каждое DHT-значение хранится на до `k = 20` узлах, ближайших к ключу. |
| **TTL-bounded storage** | Значения не хранятся вечно; они истекают после TTL, заданного publisher'ом. |
| **O(log N) lookup** | При условии, что меньше `k/2` узлов в каждом k-bucket'е — византийские, `FIND_VALUE` lookup сходится за `O(log N)` раундов. |
| **Iterative routing** | Lookup итеративный (initiator контачит узлы напрямую), а не рекурсивный; это ограничивает blast radius malicious-узла одним шагом lookup'а. |

### Что НЕ гарантируется

- **Consistency**: DHT eventually consistent; устаревшие или отсутствующие значения возможны во время churn'а.
- **Византийская толерантность сверх `k/2` на bucket**: если больше половины узлов в конкретном k-bucket'е — adversarial, lookup'ы через этот bucket могут возвращать некорректные результаты.
- **Persistence через тотальный network partition**: значения republished publisher'ом; если publisher ушёл offline до republication'а, значения теряются после истечения TTL.

### Ключевые константы

- `K = 20` — количество ближайших узлов на bucket; replication factor.
- `MAX_NODES_PER_RESPONSE = 32` — максимум контактов, возвращаемых в одном `FIND_NODE` response'е.

---

## 6. Маршрутизация

**Протокол:** relay path `DELIVERY_FORWARD` + gossip `RouteAnnounce`.

### Что гарантируется

| Гарантия | Условие |
|----------|---------|
| **Best-effort multi-path** | `RouteCache` хранит до `MAX_ROUTES_PER_DST = 4` next-hop кандидатов на destination; узел выбирает best-scoring во время отправки. |
| **Loop prevention** | Каждый relay-hop инкрементит `relay_hops`; кадры с `relay_hops >= MAX_RELAY_HOPS` отбрасываются. |
| **Split-horizon** | Кадр, полученный от peer'а P, не форвардится обратно к P (relay проверяет `via_node_id != src_peer`). |
| **TTL expiry** | Кадры с `created_at + ttl_secs < now` отбрасываются до forwarding'а; это ограничивает время жизни stale-трафика в сети. |

### Что НЕ гарантируется

- **Гарантированная доставка**: маршрутизация best-effort; кадр может быть отброшен, если маршрута нет или маршрут устарел между отправкой и доставкой.
- **Границы по latency**: SLA нет; multi-hop forwarding добавляет переменную latency в зависимости от топологии сети и congestion'а.
- **Стабильные пути**: выбор маршрута может меняться между подряд идущими кадрами на один и тот же destination.

### Ключевые константы

- `MAX_RELAY_HOPS = 16` — максимум relay-hop'ов до отброса кадра.
- `MAX_ROUTES_PER_DST = 4` — максимум next-hop кандидатов на destination в `RouteCache`.
- `MAX_ROUTES_PER_VIA = 256` — максимум destination'ов, для которых один relay-узел может быть next-hop'ом.
- `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300` — gossip-announcement'ы старше 5 минут отбрасываются.
- `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30` — future-dated gossip-announcement'ы отбрасываются.

---

## Версионирование протокола

### IPC-протокол (client ↔ node)

Версия IPC-протокола задана в `proto/ipc.rs`:

```rust
pub const IPC_PROTOCOL_VERSION: u16 = 1;  // текущая wire-версия
pub const CLIENT_MIN_VERSION: u16   = 1;  // самая старая принимаемая версия клиента
pub const CLIENT_MAX_VERSION: u16   = 1;  // самая новая принимаемая версия клиента
```

Узел отвергает клиентов, чей `version` вне `[CLIENT_MIN_VERSION, CLIENT_MAX_VERSION]`, с `ipc_hello_err::VERSION_MISMATCH`.

### OVL1 wire-протокол

Версия протокола session-слоя задана в `HelloPayload::ovl1_version`. Breaking-изменения инкрементят это поле; старые и новые узлы, которые не могут договориться об общей версии, разрывают соединение.

---

*Документ обновляется при каждом изменении сетевого контракта. Детали реализации (timeout'ы, размеры кэшей, gossip fanout) задокументированы в `proto/budget.rs` и могут меняться между релизами без предупреждения.*
