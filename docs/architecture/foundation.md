# Foundation — Архитектурные инварианты veil

Этот документ фиксирует базовые сущности, формулы и роли, которые **не пересматриваются** без очень веской причины. Он является точкой отсчёта для всех последующих эпиков.

Статус: **утверждён** (Эпик 0)

---

## 1. Identity

### 1.1 node_id

```text
node_id = BLAKE3(raw_public_key_bytes)   // 32 bytes
```

**Реализация в коде:** `cfg::model::NodeId::from_public_key(algo, base64_pubkey)`
→ декодирует base64 → берёт BLAKE3 от raw bytes → возвращает `[u8; 32]`.

**Что зафиксировано:**
- `node_id` — стабильный глобальный идентификатор узла
- Привязан к криптографическому публичному ключу
- Не зависит от транспорта, IP-адреса, топологии
- Алгоритм хэширования: BLAKE3, входной материал: raw bytes (не base64-строка)

**Что НЕ является `node_id`:**
- IP-адрес / hostname
- DHT position (node_id используется как DHT key напрямую, но это совпадение, не определение)
- Runtime identifier (LinkId, PeerId — отдельные понятия)

### 1.2 node_addr

```text
node_addr := node_id
```

Отдельного «магического» адреса узла не существует.

- `node_id` — глобальный стабильный адрес
- текущая достижимость (transport endpoints) — runtime state, не часть identity
- attachment/gateway/mailbox refs — отдельные записи поверх

### 1.3 app_id

```text
app_id = BLAKE3-derive_key(
    "veil.app_id.v1",
    node_id || ns_len(u32 BE) || app_namespace || name_len(u32 BE) || app_name
)
```

Length-prefixes обязательны: без них `("foo","bar")` и `("fo","obar")` склеивались
бы в одну и ту же строку и давали коллизию по `app_id` (Epic 452).

Адрес конечной точки приложения:

```rust
AppAddress {
    node_id:     [u8; 32],
    app_id:      [u8; 32],
    endpoint_id: u32,
}
```

`AppAddress` фиксируется как vocabulary. Реализация — Эпик 6.

### 1.4 content_id

```text
// Простая форма:
content_id = BLAKE3(content_bytes)

// С domain separation:
content_id = BLAKE3(app_id || content_type || payload)
```

---

## 2. Роли узлов

Ровно четыре роли. Один бинарник — все роли.

### Leaf

Слабый / мобильный / периодически офлайн-узел.

- Нет публичной достижимости (может не быть)
- Не участвует в DHT ownership
- Не хранит чужие записи
- Работает через Core-ноды и mailbox

### Core

Полноправный участник сети.

- Участвует в DHT (K=20), relay/forwarding
- Gateway: публикует attachment records leaf-узлов (отключается через конфиг)
- Хранит mailbox shards для офлайн-получателей
- NAT relay для leaf-узлов за NAT
- Mesh bridge (опционально, по конфигу)
- Требует PoW ≥ 24 бит, высокого uptime

---

## 3. Plane model

Семь плоскостей. Каждая — отдельная зона ответственности.

| Plane | Назначение |
|---|---|
| **transport plane** | Raw byte streams / datagrams между узлами |
| **session/security plane** | Identity, key agreement, session lifecycle |
| **veil control plane** | Keepalive, ping/pong, neighbor offers, route probes |
| **discovery plane** | DHT lookup, attachment records, app endpoint records |
| **delivery plane** | Mailbox, forward, store-and-forward |
| **local mesh plane** | BLE/Wi-Fi Direct, local ad-hoc, realm membership |
| **application plane** | APP_OPEN/APP_DATA/APP_CLOSE, app demux |

Плоскости не смешиваются в одном компоненте без явной причины.

---

## 4. DHT и масштаб

### Кто участвует в DHT ownership

| Роль | DHT owner |
|---|---|
| `core` | ✅ да (K=20) |
| `leaf` | ❌ **никогда** |

`leaf` — это подавляющее большинство устройств в сети. Именно поэтому DHT не масштабируется линейно с числом устройств.

### DHT метрика

```text
distance(a, b) = a XOR b   // XOR-space, как Kademlia
```

### DHT ключи

```text
node routing key      = node_id
attachment key        = BLAKE3("attach"  || node_id)
mailbox key           = BLAKE3("mailbox" || node_id || epoch)
app endpoint key      = BLAKE3("app"     || node_id || app_id || endpoint_id)
```

---

## 5. Vivaldi — только optimization hint

Vivaldi (или любая coordinate-based latency estimation) **не используется** как:

- `node_id`
- DHT placement key
- ownership-space identifier
- trust anchor

Vivaldi используется **только** как performance hint:

- выбор ближайшего gateway
- ранжирование mailbox replicas
- ранжирование соседей / relays
- route scoring

Это не часть протокола до Эпика 12.

---

## 6. Что можно ломать по дороге

| Можно временно | Нельзя без очень веской причины |
|---|---|
| Текущую модель configured peers | `node_id = BLAKE3(pubkey)` |
| Внутренние форматы admin-сокета | transport abstraction layer |
| Старые debug-only session semantics | role/plane separation после утверждения |
| Внутренние структуры NodeMetrics | принцип «Vivaldi не в ownership» |

---

## 7. Соответствие коду

| Инвариант | Код |
|---|---|
| `node_id = BLAKE3(pubkey)` | `cfg::model::NodeId::from_public_key` |
| `NodeId` = `[u8; 32]` | `cfg::model::NodeId([u8; 32])` |
| NodeId display = hex-64 | `impl fmt::Display for NodeId` |
| node_id вычисляется при валидации | `cfg::validate::structural::fix_invalid_node_id` |
| Transport abstraction | `transport::traits::{Transport, TransportConnection, TransportListener}` |
| Transport registry | `transport::registry::TransportRegistry` |
| Session identity | `node::handshake::HandshakeFrame` |

---

*Следующий шаг: Эпик 1 — бинарный протокол OVL1 (`crates/veil-proto/src/`)*
