# Foundation — архитектурные инварианты veil

Инвариант — это правило, которое мы держим неизменным. Этот документ фиксирует базовые сущности, формулы и роли, которые **не пересматриваются** без очень веской причины. Он — точка отсчёта для всех последующих эпиков.

Статус: **утверждён** (Эпик 0)

---

## 1. Identity

### 1.1 node_id

```text
node_id = BLAKE3(raw_public_key_bytes)   // 32 bytes
```

**Реализация в коде:** `cfg::model::NodeId::from_public_key(algo, base64_pubkey)`
декодирует base64, берёт BLAKE3 от сырых байтов и возвращает `[u8; 32]`.

**Что зафиксировано:**
- `node_id` — стабильный глобальный идентификатор узла.
- Привязан к криптографическому публичному ключу.
- Не зависит от транспорта (способа передачи), IP-адреса и топологии.
- Алгоритм хэширования — BLAKE3. На вход идут сырые байты, а не строка base64.

**Что `node_id` НЕ является:**
- IP-адресом или именем хоста.
- Позицией в DHT. Да, `node_id` напрямую служит ключом DHT, но это совпадение, а не определение.
- Идентификатором времени выполнения (`LinkId`, `PeerId` — отдельные понятия).

### 1.2 node_addr

```text
node_addr := node_id
```

Отдельного «магического» адреса узла не существует.

- `node_id` — глобальный стабильный адрес.
- Текущая достижимость (точки входа транспорта) — это изменчивое состояние, а не часть личности узла.
- Ссылки на attachment, gateway и mailbox — отдельные записи поверх этого адреса.

### 1.3 app_id

```text
app_id = BLAKE3-derive_key(
    "veil.app_id.v1",
    node_id || ns_len(u32 BE) || app_namespace || name_len(u32 BE) || app_name
)
```

Префиксы длины обязательны. Без них `("foo","bar")` и `("fo","obar")` склеились
бы в одну и ту же строку и дали бы коллизию по `app_id` (Эпик 452).

Адрес конечной точки приложения:

```rust
AppAddress {
    node_id:     [u8; 32],
    app_id:      [u8; 32],
    endpoint_id: u32,
}
```

`AppAddress` фиксируется как термин. Реализация — Эпик 6.

### 1.4 content_id

```text
// Простая форма:
content_id = BLAKE3(content_bytes)

// С domain separation:
content_id = BLAKE3(app_id || content_type || payload)
```

---

## 2. Роли узлов

Ровно четыре роли. Бинарник один — роли все.

### Leaf

Слабый, мобильный или периодически уходящий в офлайн узел.

- Публичной достижимости может не быть.
- Не владеет участком DHT.
- Не хранит чужие записи.
- Работает через узлы Core и через mailbox (почтовый ящик).

### Core

Полноправный участник сети.

- Участвует в DHT (K=20), пересылает чужой трафик.
- Шлюз: публикует записи attachment для узлов Leaf (отключается в конфиге).
- Хранит куски mailbox для получателей, которые сейчас офлайн.
- Служит NAT-ретранслятором для узлов Leaf за NAT.
- При желании работает мостом в локальную mesh-сеть (по конфигу).
- Требует PoW не ниже 24 бит и высокого аптайма.

---

## 3. Plane model

Семь плоскостей. Плоскость — это отдельная зона ответственности.

| Plane | Назначение |
|---|---|
| **transport plane** | Raw byte streams / datagrams между узлами |
| **session/security plane** | Identity, key agreement, session lifecycle |
| **veil control plane** | Keepalive, ping/pong, neighbor offers, route probes |
| **discovery plane** | DHT lookup, attachment records, app endpoint records |
| **delivery plane** | Mailbox, forward, store-and-forward |
| **local mesh plane** | BLE/Wi-Fi Direct, local ad-hoc, realm membership |
| **application plane** | APP_OPEN/APP_DATA/APP_CLOSE, app demux |

Без явной причины плоскости не смешиваются в одном компоненте.

---

## 4. DHT и масштаб

### Кто владеет участками DHT

| Роль | Владеет участком DHT |
|---|---|
| `core` | ✅ да (K=20) |
| `leaf` | ❌ **никогда** |

Узлы `leaf` — это подавляющее большинство устройств в сети. Именно поэтому размер DHT не растёт линейно с числом устройств.

### Метрика DHT

```text
distance(a, b) = a XOR b   // XOR-space, как Kademlia
```

### Ключи DHT

```text
node routing key      = node_id
attachment key        = BLAKE3("attach"  || node_id)
mailbox key           = BLAKE3("mailbox" || node_id || epoch)
app endpoint key      = BLAKE3("app"     || node_id || app_id || endpoint_id)
```

---

## 5. Vivaldi — только подсказка для оптимизации

Vivaldi (как и любая оценка задержки через координаты) **не используется** как:

- `node_id`;
- ключ размещения в DHT;
- идентификатор участка владения;
- якорь доверия.

Vivaldi нужен **только** как подсказка для производительности:

- выбрать ближайший шлюз;
- ранжировать копии mailbox;
- ранжировать соседей и ретрансляторы;
- оценить маршрут.

В протокол это не входит вплоть до Эпика 12.

---

## 6. Что можно ломать по дороге

| Можно ломать временно | Нельзя без очень веской причины |
|---|---|
| Текущую модель заданных в конфиге соседей | `node_id = BLAKE3(pubkey)` |
| Внутренние форматы admin-сокета | абстракцию транспорта (слой над способом передачи) |
| Старую отладочную семантику сессий | разделение ролей и плоскостей после утверждения |
| Внутренние структуры `NodeMetrics` | принцип «Vivaldi не участвует во владении» |

---

## 7. Соответствие коду

| Инвариант | Код |
|---|---|
| `node_id = BLAKE3(pubkey)` | `cfg::model::NodeId::from_public_key` |
| `NodeId` = `[u8; 32]` | `cfg::model::NodeId([u8; 32])` |
| Вывод `NodeId` — это hex длиной 64 | `impl fmt::Display for NodeId` |
| `node_id` вычисляется при валидации | `cfg::validate::structural::fix_invalid_node_id` |
| Абстракция транспорта | `transport::traits::{Transport, TransportConnection, TransportListener}` |
| Реестр транспортов | `transport::registry::TransportRegistry` |
| Личность сессии | `node::handshake::HandshakeFrame` |

---

*Следующий шаг — Эпик 1: бинарный протокол OVL1 (`crates/veil-proto/src/`).*
