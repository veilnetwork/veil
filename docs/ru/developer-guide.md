# Руководство разработчика

## Структура проекта

Проект — это workspace из множества крейтов `crates/veil-*`. Реализации
живут в этих крейтах; `veilcore/` теперь тонкий фасадный крейт-агрегатор,
а бинарник `veil-cli` вынесен в отдельный крейт `crates/veil-cli`.

```
veil/
├── crates/                     # Workspace-крейты с реализациями
│   ├── veil-cli/            # Бинарник veil-cli + CLI-команды (clap)
│   │   ├── src/bin/cli.rs      # Точка входа бинарника veil-cli
│   │   ├── src/cmd/            # CLI-команды
│   │   └── Cargo.toml
│   ├── veil-proto/          # Wire-форматы (encode/decode), family.rs, budget.rs
│   ├── veil-transport/      # Транспортные адаптеры (TCP/TLS/QUIC/WS/SOCKS, Unix)
│   ├── veil-session/        # OVL1-handshake, FSM, runner, handoff
│   ├── veil-dispatcher/     # Маршрутизация фреймов (FrameDispatcher)
│   ├── veil-dht/            # Kademlia DHT (K=20), TieredStore
│   ├── veil-discovery/      # Directory-сервис (attachment, endpoint)
│   ├── veil-gateway/        # Управление leaf-подключениями
│   ├── veil-ipc/            # IPC-сервер (Unix socket) для приложений
│   ├── veil-mailbox/        # Хранилище сообщений (redb)
│   ├── veil-mesh/           # Локальная UDP-сеть, беаконы
│   ├── veil-nat/            # NAT-траверсал
│   ├── veil-pex/            # Peer Exchange
│   ├── veil-proxy/          # SOCKS5-прокси через veil
│   ├── veil-routing/        # RouteCache, RTT-таблица, Vivaldi
│   ├── veil-crypto/         # Криптографические примитивы, PoW
│   ├── veil-cfg/            # Конфигурация (модель, парсинг, валидация)
│   ├── veil-identity/       # Identity, name_access, network_access
│   ├── veil-node-runtime/   # NodeRuntime, admin API, metrics_http
│   ├── veil-observability/  # Метрики и логирование
│   ├── ogate/                  # Gateway-бинарник; TUN/TAP в src/tun/
│   └── …                       # ещё ~40 крейтов veil-*
├── veilcore/                # Фасадный крейт-агрегатор (re-export shim'ы)
│   ├── src/
│   │   ├── lib.rs              # Экспорты, макрос lock!
│   │   ├── node/*.rs          # Плоские re-export файлы (dht.rs, control.rs, …)
│   │   │                      #   — фасады над крейтами veil-*
│   │   ├── proto.rs           # Re-export veil-proto (один файл, не каталог)
│   │   └── transport.rs       # Re-export shim над veil-transport
│   └── Cargo.toml
├── veilclient/              # Client SDK для приложений
├── fuzz/                       # Fuzzing-харнессы
├── docs/                       # Документация (этот каталог)
└── specification.md            # Исходная спецификация (RU)
```

> Примечание: бинарник теперь — `crates/veil-cli` (`src/bin/cli.rs`).
> `veilcore/src/node/*.rs` и `crates/veil-proto/src/lib.rs` — это re-export
> фасады над крейтами `crates/veil-*` (veil-dht, veil-session,
> veil-proto, veil-transport и т.д.); каталог `crates/veil-cli/src/bin/`
> отсутствует.

---

## Архитектура

### Слои системы

```
┌──────────────────────────────────────────────────────┐
│                  Application Layer                   │
│  Local apps via IPC (Unix socket) / veilclient SDK   │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│               Node Runtime (runtime.rs)              │
│  Event loop, session lifecycle, background tasks     │
└────┬──────────────────┬──────────────────────────────┘
     │                  │
┌────▼────┐    ┌────────▼─────────────────────────────────┐
│Session  │    │         FrameDispatcher                  │
│Manager  │    │  Control │ Discovery │ Delivery │ Routing│
│handshake│    └──────────┬───────────────────────────────┘
│FSM      │               │
└─────────┘   ┌───────────▼───────────────────────────────┐
              │           Services                        │
              │ DHT │ Mailbox │ Gateway │ AppRegistry │.. │
              └───────────────────────────────────────────┘
```

### Основные компоненты

---

## NodeRuntime (`node/runtime.rs`, ~7600 строк)

Центральный event loop. Реализует:

- **Lifecycle**: запуск/остановка слушателей, подключение к пирам, обработка сигналов (SIGHUP)
- **Session management**: accept входящих → handshake → регистрация; reconnect исходящих с exponential backoff
- **Background tasks**: DHT republish, gateway cleanup, mailbox cleanup, периодическое сохранение состояния (routes, RTT, Vivaldi, gateways, peer pubkeys)
- **Frame dispatch**: после handshake передаёт декодированные фреймы в `FrameDispatcher`

**Ключевые структуры:**

```rust
struct NodeServices {
    local_identity: Arc<LocalIdentity>,
    dispatcher: Arc<FrameDispatcher>,
    session_registry: Arc<Mutex<SessionRegistry>>,
    app_registry: Arc<AppEndpointRegistry>,
    dht: Arc<KademliaService>,
    mailbox: Arc<MailboxService>,
    gateway: Arc<GatewayService>,
    discovery: Arc<DiscoveryService>,
    routing: Arc<RoutingService>,
    metrics: Option<Arc<NodeMetrics>>,
    // ... ещё ~15 Arc-полей
}

struct SessionRuntimeContext {
    peer_node_id: [u8; 32],
    session_keys: SessionKeys,
    outbox: Arc<SessionOutbox>,
    role: NodeRole,
    // Разделяемые сервисы (clone Arc, не копия данных)
}
```

**При добавлении нового сервиса:**
1. Добавьте поле `Arc<YourService>` в `NodeServices`
2. Инициализируйте в `NodeRuntime::new()`
3. При необходимости передайте в `SessionRuntimeContext` через `spawn_session_runner()`
4. Добавьте фоновую задачу в `NodeRuntime::run_inner()` если нужно

---

## FrameDispatcher (`node/dispatcher/mod.rs`)

Получает декодированный фрейм от session runner'а и маршрутизирует по `family`:

```rust
pub async fn dispatch(
    &self,
    frame: ParsedFrame,
    ctx: &SessionRuntimeContext,
) -> Option<EncodedFrame> // Some = ответ отправить назад
```

**Структура dispatcher'а:**

```
dispatcher/
├── mod.rs                    # Основной dispatch + pending_diag
├── app.rs                    # App-plane (потоки)
├── control.rs                # Control-plane (ping, neighbor, probe)
├── delivery.rs               # Delivery-plane (mailbox, forward, trace)
├── discovery.rs              # DHT (FindNode, Store, Delete, Announce)
├── routing.rs                # RouteAnnounce, RouteRequest, PoW
├── session.rs                # Keepalive, Rekey, Detach
├── diag.rs                   # DiagPing, DiagTrace
├── pending_ack.rs            # Трекинг require_ack сообщений
├── pending_fetch_replica.rs  # Трекинг reseed MAILBOX_FETCH на replica-ноды
└── pending_replica.rs        # Трекинг MAILBOX_REPLICATE между Core-нодами
```

**При добавлении нового типа фрейма:**

1. Добавьте новый `msg_type` в `proto/family.rs` (enum + TryFrom)
2. Добавьте decode-метод в соответствующем `proto/` файле
3. В `dispatcher/mod.rs` добавьте ветку в `match frame.family`
4. В соответствующем `dispatcher/*.rs` реализуйте обработчик
5. Напишите тест в `#[cfg(test)] mod tests`

---

## Session Layer (`node/session/`)

```
session/
├── mod.rs          # Re-exports, SessionRegistry
├── handshake.rs    # OVL1-handshake (perform_ovl1_handshake)
├── fsm.rs          # Finite State Machine handshake-фаз
├── runner.rs       # Long-lived session task (чтение/запись фреймов)
└── outbox.rs       # Thread-safe очередь для отправки фреймов
```

### Handshake

```rust
pub async fn perform_ovl1_handshake(
    stream: &mut BoxIoStream,
    identity: &HandshakeIdentity,
    role: NodeRole,
    local_mlkem_ek: Option<&[u8]>,
    // ...
) -> Result<OvlHandshakeResult>
```

Возвращает `OvlHandshakeResult` с `session_keys`, `node_id`, `remote_role`, `remote_identity_payload`, `remote_capabilities`, `remote_attach`.

### Session Runner

После handshake создаётся `SessionRunner`:

1. Читает фреймы из транспорта
2. Декодирует заголовок + тело
3. Проверяет ChaCha20-Poly1305 MAC (если `flags.encrypted`)
4. Вызывает `FrameDispatcher::dispatch()`
5. Отправляет ответ через `SessionOutbox`
6. Проверяет keepalive/idle timeout

**Приоритизация фреймов**: Weighted Round-Robin по `flags.priority`:
- RT (0): weight 8
- Interactive (1): weight 4
- Bulk (2): weight 2
- Background (3): weight 1

---

## Proto Layer (`proto/`)

Wire-форматы реализованы без внешних библиотек — только `encode() → Vec<u8>` и `decode(&[u8]) → Result<Self, ProtoError>`.

```
proto/
├── mod.rs           # Общие утилиты: read_u16_be, read_array, etc.
├── budget.rs        # Все константы-лимиты
├── codec.rs         # MAX_FRAME_BODY, фреймовый кодек
├── header.rs        # FrameHeader (24 байта)
├── family.rs        # ControlMsg, LocalAppMsg, RoutingMsg enums
├── session.rs       # Hello, Identity, Capabilities, KeyAgreement, ATTACH
├── control.rs       # NeighborOffer, RouteProbe/Reply, NAT payloads
├── delivery.rs      # DeliveryEnvelope, MailboxFetch, MailboxAck
├── discovery.rs     # FindNode, Store, AnnounceAttachment, DhtValue
├── routing.rs       # RouteAnnounce, RouteRequest, RouteResponse
├── epidemic.rs      # EpidemicPayload
├── e2e.rs           # E2eEnvelope (ML-KEM + ChaCha20-Poly1305 wrapper)
├── mesh.rs          # MeshFrame, MeshBeaconPayload, MeshAckPayload
├── name.rs          # NameRecord (human-readable names)
├── app.rs           # App-plane полезные нагрузки
├── diag.rs          # DiagPingPayload, DiagTracePayload
├── anycast.rs       # AnycastRequest / AnycastResponse
├── ipc.rs           # LocalApp IPC-сообщения (app ↔ node)
├── pex.rs           # PEX-обмен пирами
├── relay_chain.rs   # RecursiveRelay header/onion
└── golden_tests.rs  # Golden-векторы wire-форматов
```

### Правила при добавлении нового payload:

```rust
// 1. Структура с pub полями
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyPayload {
    pub field1: [u8; 32],
    pub field2: u16,
    pub variable: Vec<u8>,
}

// 2. impl с encode/decode
impl MyPayload {
    // ВСЕГДА добавляйте assert перед as u16 / as u8 кастами!
    pub fn encode(&self) -> Vec<u8> {
        assert!(
            self.variable.len() <= u16::MAX as usize,
            "MyPayload: variable exceeds u16::MAX bytes"
        );
        let mut buf = Vec::with_capacity(32 + 2 + 2 + self.variable.len());
        buf.extend_from_slice(&self.field1);
        buf.extend_from_slice(&self.field2.to_be_bytes());
        buf.extend_from_slice(&(self.variable.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.variable);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        const MIN: usize = 32 + 2 + 2;
        if buf.len() < MIN {
            return Err(ProtoError::BufferTooShort { need: MIN, got: buf.len() });
        }
        let field1 = super::read_array::<32>(buf, 0)?;
        let field2 = super::read_u16_be(buf, 32)?;
        let var_len = super::read_u16_be(buf, 34)? as usize;
        if buf.len() < 36 + var_len {
            return Err(ProtoError::BufferTooShort { need: 36 + var_len, got: buf.len() });
        }
        Ok(Self { field1, field2, variable: buf[36..36 + var_len].to_vec() })
    }
}

// 3. Тесты (обязательно!)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = MyPayload { field1: [1u8; 32], field2: 42, variable: b"test".to_vec() };
        assert_eq!(MyPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn decode_too_short() {
        assert!(MyPayload::decode(&[0u8; 5]).is_err());
    }
}
```

---

## Ключевые сервисы

### MailboxService (`node/mailbox/`)

Интерфейс:
```rust
pub trait MailboxBackend: Send + Sync {
    fn put(&self, envelope: DeliveryEnvelope) -> Option<u64>;        // → seq
    fn fetch(&self, recipient: &[u8; 32], after_seq: u64) -> Vec<MailboxEntry>;
    fn ack(&self, recipient: &[u8; 32], up_to_seq: u64);
    fn ack_batch(&self, recipient: &[u8; 32], seqs: &[u64]);
    fn senders_for_seqs(&self, recipient: &[u8; 32], seqs: &[u64]) -> Vec<[u8; 32]>;
    fn cleanup_expired(&self, now: Instant);
    fn total_entries(&self) -> usize;
    fn recipient_count(&self) -> usize;
}
```

Добавление нового backend'а:
1. Реализуйте `MailboxBackend` в `node/mailbox/`
2. Добавьте вариант в `MailboxBackendKind` enum
3. Добавьте строку `"yourbackend"` в парсер в `MailboxService::new()`

### AppEndpointRegistry (`node/app/registry.rs`)

Мультиплексирует IPC-сообщения к зарегистрированным приложениям:

```rust
pub struct AppEndpointRegistry { ... }

impl AppEndpointRegistry {
    pub fn register(&self, app_id: [u8; 32], endpoint_id: u32)
        -> (EndpointHandle, mpsc::Receiver<AppMessage>);

    pub fn route(&self, msg: AppMessage) -> bool; // true = доставлено

    pub fn route_delivery_failed(&self, src_app_id: [u8; 32], content_id: [u8; 32]);
}
```

### KademliaService (`node/dht/`)

```rust
impl KademliaService {
    pub async fn find_node(&self, target: [u8; 32], local_id: [u8; 32])
        -> Vec<Contact>;

    pub fn find_value_local(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
    pub fn store_local(&self, key: [u8; 32], value: Vec<u8>, ttl_secs: u32);
    pub fn add_contact(&self, contact: Contact);
}
```

**Внимание:** Кросс-узловые итеративные lookup (`find_value` по сети) требуют отправки фреймов через сессии. Запрашивайте через `dispatcher/discovery.rs`, а не напрямую через `KademliaService`.

### RouteCache (`node/routing/cache.rs`)

```rust
impl RouteCache {
    pub fn insert(&mut self, dst: [u8; 32], via: [u8; 32], score: f64, hops: u8);
    pub fn lookup(&self, dst: &[u8; 32]) -> Option<&RouteCacheEntry>;
    pub fn lookup_all_with_scores(&self, dst: &[u8; 32]) -> Vec<([u8;32], f64)>;
    pub fn evict_expired(&mut self, now: Instant);
}
```

ECMP: при нескольких путях с `score` в пределах `ecmp_score_band` (±20%) выбирается случайный.

### ControlPlaneService (`node/control.rs`)

Управляет RTT-измерениями (RouteProbe/Reply):

```rust
impl ControlPlaneService {
    pub fn handle_probe(&self, payload: &RouteProbePayload) -> RouteReplyPayload;
    pub fn handle_reply(&self, peer_id: [u8; 32], payload: &RouteReplyPayload);
    pub fn rtt_table(&self) -> Arc<Mutex<RttTable>>;
}
```

---

## Паттерны проекта

### Макрос `lock!`

Все блокировки Mutex выполняются через `lock!`:

```rust
// Правильно:
let mut table = lock!(self.route_cache);
table.insert(...);

// Неправильно (паника при отравленном mutex):
self.route_cache.lock().unwrap()
```

Макрос восстанавливается от отравленного mutex с предупреждением в лог. Определён в `lib.rs`.

### `Arc<Mutex<_>>` vs `Arc<RwLock<_>>`

- `Arc<Mutex<_>>` — стандарт для mutable state (всегда)
- `Arc<RwLock<_>>` — только если доказанно читается многократно без записи (редко)
- Все `Arc<Mutex<_>>` используются с `lock!` (не `.lock().unwrap()`)

### Hex-форматирование

Используйте утилиты из крейта `veil-util`:

```rust
// 32-байтный ID (полный hex, 64 символа)
veil_util::hex_str(&node_id)

// Первые 4 байта (для логов)
veil_util::hex_short(&node_id)

// НЕ ДЕЛАЙТЕ так (дублирование кода):
node_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
```

### Производительность и размер cast'ов

**Обязательно** проверяйте перед `as u16` / `as u8`:

```rust
// Правильно:
assert!(data.len() <= u16::MAX as usize, "MyMsg: data exceeds u16::MAX");
let len = data.len() as u16;

// Неправильно (silent truncation при data.len() > 65535):
let len = data.len() as u16;
```

### Логирование

Проект использует крейт `log` (не `tracing`):

```rust
log::debug!("route.cache.insert dst={} via={} score={}", hex_short(&dst), hex_short(&via), score);
log::info!("session.established peer={}", hex_short(&peer_id));
log::warn!("mailbox.put.failed reason={}", e);
log::error!("config.save.failed: {e}");
```

### Async и blocking

- Вся I/O — async через tokio
- Тяжёлые вычисления (PoW, Falcon512 keygen) → `tokio::task::spawn_blocking`
- `Mutex` (не `tokio::sync::Mutex`) — для коротких критических секций

---

## Добавление нового функционала

### Чеклист при добавлении нового сообщения протокола

- [ ] `proto/family.rs`: добавить вариант в enum + `TryFrom<u16>`
- [ ] `proto/`: создать/дополнить файл с `encode()`/`decode()` + unit-тест
- [ ] `proto/budget.rs`: добавить константы лимитов если нужно
- [ ] `dispatcher/mod.rs`: добавить ветку dispatch
- [ ] `dispatcher/NEW.rs`: реализовать обработчик
- [ ] `node/runtime.rs`: wire в SessionRuntimeContext если нужно
- [ ] Написать интеграционный тест

### Чеклист при добавлении нового конфиг-поля

- [ ] `cfg/model.rs`: добавить поле в соответствующую Config-структуру
- [ ] Значение по умолчанию через `#[serde(default = "...")]`
- [ ] `cfg/validate/`: добавить валидацию если нужно
- [ ] `cfg/access.rs`: добавить `ConfigKey` вариант для get/set через CLI
- [ ] Документация в [admin-guide.md](admin-guide.md)

### Чеклист при добавлении нового сервиса

- [ ] Создать `node/myservice/mod.rs` с `pub(crate) struct MyService`
- [ ] Сделать `Clone-cheap` через `Arc<Mutex<Inner>>`
- [ ] Добавить в `NodeServices` как `Arc<MyService>`
- [ ] Инициализировать в `NodeRuntime::new()`
- [ ] Добавить `Arc::clone` в нужных местах (не передавать по значению)
- [ ] Фоновую задачу добавить в `run_inner()` через `tokio::spawn`
- [ ] Unit-тест в `#[cfg(test)]`

---

## Тестирование

### Структура тестов

```
veilcore/src/
├── proto/*/tests      # Unit-тесты wire-форматов (roundtrip, too-short, etc.)
├── node/*/tests       # Unit-тесты сервисов
└── integration/       # Интеграционные тесты (полный handshake, multi-hop)
```

### Полезные утилиты для тестов

**Создание тестового dispatcher'а:**

```rust
// В #[cfg(test)]:
use crate::node::dispatcher::make_test_dispatcher;
let dispatcher = make_test_dispatcher(NodeRole::Core);
```

**Duplex-поток для handshake-тестов:**

```rust
let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
let client = tokio::spawn(async move {
    perform_ovl1_handshake(&mut client_stream, &identity_a, NodeRole::Leaf, ...).await
});
let server = tokio::spawn(async move {
    perform_ovl1_handshake(&mut server_stream, &identity_b, NodeRole::Core, ...).await
});
```

**Запуск тестов:**

```bash
cargo test --workspace                    # Все тесты
cargo test --package veilcore          # Только veilcore
cargo test proto::delivery               # Конкретный модуль
cargo test -- --nocapture                # С выводом stdout
```

**Фаззинг:**

```bash
# Список всех харнессов — в fuzz/Cargo.toml
cargo fuzz run fuzz_session_decode
cargo fuzz run fuzz_delivery_decode
cargo fuzz run fuzz_routing_decode
cargo fuzz run fuzz_app_decode
cargo fuzz run fuzz_ipc_decode
cargo fuzz run fuzz_cipher_open
cargo fuzz run fuzz_proto_decode
```

---

## Известные ограничения и заглушки

Следующие компоненты являются **стабами** или имеют неполную реализацию:

| Компонент | Файл | Статус |
|-----------|------|--------|
| Mesh WiFi Direct / BLE | отсутствует | Реальная интеграция не реализована; mesh работает поверх UDP-линков ([`node/mesh/udp.rs`](../../crates/veil-mesh/src/udp.rs)) |
| QUIC-сессии | [`transport/quic.rs`](../../crates/veil-transport/src/quic.rs) | Транспорт `quic://` компилируется всегда (безусловная зависимость `quinn`); отдельного feature-флага больше нет |
| PoW signature verify | [`node/dispatcher/routing.rs`](../../crates/veil-dispatcher/src/routing.rs) | Подпись PowChallenge не верифицируется в некоторых путях |
| TUN/TAP | [`crates/ogate/src/tun/`](../../crates/ogate/src/tun/) | Базовая реализация в крейте `ogate` (вынесена из `veilcore`); продакшн-готовность не проверялась |

---

## Взаимодействие компонентов

### Жизненный цикл входящего сообщения (DeliveryEnvelope)

```
Network → TransportLayer
  → SessionRunner.read_frame()
    → FrameDispatcher.dispatch(family=Delivery, msg_type=MailboxPut)
      → dispatcher/delivery.rs::handle_mailbox_put()
        → MailboxService.put(envelope)
          → MailboxBackend.put()  [memory/wal/rocksdb]
        → DeliveryStatusPayload(OK)
      → encode_response()
  → SessionOutbox.send(response)
→ Network
```

### Жизненный цикл IPC-сообщения от приложения

```
App (Unix socket)
  → IpcServer.accept()
    → IpcHandler.handle_app_bind()
      → AppEndpointRegistry.register(app_id, endpoint_id)
    → IpcHandler.handle_app_send(target_node_id, payload)
      → E2eService.encrypt(payload, recipient_ek)  [если enabled]
      → DeliveryEnvelope { recipient, sender, payload, ... }
      → SessionRegistry.find_session(target_node_id)
        → SessionOutbox.send(frame)  [если сессия есть]
        → MailboxService.put(envelope)  [если нет сессии - через gateway]
```

### Жизненный цикл DHT-lookup

```
DiscoveryService.handle_find_value_request(key)
  → KademliaService.find_value_local(key)
    → Some(value) → FindValueResponse::Value
    → None → KademliaRoutingTable.closest(key, k=20)
      → FindValueResponse::Nodes [k closest contacts]

  [Клиент рекурсивно повторяет FindValue до нужного узла]
```

### Route Discovery

```
RoutingService.discover_route(target_node_id)
  → PowChallenge.solve()  [если требуется]
  → RouteDiscoveryPacket { target, requester, ttl=16, pow_solution }
  → broadcast to N random neighbors

[Каждый промежуточный узел:]
  → PoW verify
  → If target == self: send RouteDiscoverOffer back
  → Else: forward to closest neighbor, decrement TTL

[Requester получает RouteDiscoverOffer:]
  → RouteCache.insert(target, via=offer_sender, score)
  → Notify waiting sender
```

---

## Добавление нового транспорта

Для добавления нового транспорта (например, BLUETOOTH_TCP):

1. Реализуйте `TransportConnection` trait в `transport/`:

```rust
pub trait TransportConnection: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn peer_addr(&self) -> Option<SocketAddr>;
    fn local_addr(&self) -> Option<SocketAddr>;
}
```

2. Реализуйте `TransportListener` trait:

```rust
pub trait TransportListener: Send + 'static {
    async fn accept(&mut self) -> Result<(Box<dyn TransportConnection>, SocketAddr)>;
}
```

3. Зарегистрируйте в `TransportRegistry` с URI-схемой:

```rust
registry.register("bt", Box::new(BluetoothTransportFactory));
```

4. Добавьте парсинг в `cfg/model.rs::ListenConfig::transport`

5. Добавьте в документацию транспортов

---

## Feature-флаги сборки

Проект использует Cargo feature-флаги для опциональных зависимостей. Важно
различать **крейт-библиотеку** `veilcore` и **пользовательский бинарник**
`veil-cli` (`crates/veil-cli`) — у них разные дефолты:

- `veilcore` (библиотека): `default = ["rocksdb-cold"]`.
- `veil-cli` (бинарник, который собирают и запускают пользователи):
  `default = ["rocksdb-cold", "tls-boring"]`. То есть в поставляемых сборках
  BoringSSL и его браузероподобный JA3/JA4-fingerprint ClientHello (с ротацией)
  включены **по умолчанию**; `rustls` остаётся fallback'ом через
  `--no-default-features`.

| Флаг | Крейт | Эффект |
|------|-------|--------|
| `rocksdb-cold` (default) | `veilcore`, `veil-cli` | Включает RocksDB-бэкенд для cold-хранилищ (mailbox, DHT cold tier). Требует `librocksdb`. |
| `tls-boring` (default у `veil-cli`) | `veilcore`, `veil-cli` | Заменяет `rustls` на BoringSSL (`btls`/`tokio-btls`/`quinn-btls`); даёт Chrome-подобный JA3/JA4 ClientHello-fingerprint + ротацию (базовый путь обхода DPI). У `veilcore` off по умолчанию, у `veil-cli` — on. |
| `tls-webpki-roots` | `veilcore`, `veil-cli` | Semver-стабильный no-op для существующих конфигов сборки (webpki-roots всегда присутствует в бинарнике для HTTPS-bootstrap). |
| `production-seeds` | `veilcore`, `veil-cli` | Встраивает production seed-узлы в бинарник. |
| `allow-empty-seeds` | `veilcore`, `veil-cli` | Разрешает запуск без seeds (только для dev/test). |
| `test-low-difficulty` | `veilcore`, `veil-cli` | Снижает PoW-сложность identity до 16 бит для devnet/тестов (в продакшене — 24 бита). |
| `slow-sim-tests` | `veilcore`, `veil-cli` | Включает тяжёлые sim-тесты (≥55 с), иначе `#[ignore]`d. |

> QUIC и TUN/TAP **не** управляются feature-флагами: транспорт `quic://`
> компилируется всегда (безусловная зависимость `quinn`), а TUN/TAP вынесен
> в крейт `crates/ogate` (`src/tun/`).

### Сборка с флагами

```bash
# Стандартная сборка бинарника (rocksdb-cold + tls-boring по умолчанию)
cargo build -p veil-cli

# Без дефолтных фич: возвращает rustls-стек (один немутирующий fingerprint)
cargo build -p veil-cli --no-default-features --features rocksdb-cold

# Сборка только библиотеки veilcore (default = rocksdb-cold)
cargo build -p veilcore

# Сборка бинарника, пригодная для production
cargo build -p veil-cli --features production-seeds

# Проверка без сборки
cargo check -p veil-cli --no-default-features
```

### Сборка на Windows (нативно)

CI собирает весь workspace на Linux; джоба `windows-test` намеренно использует
`-p veilcore --no-default-features`, чтобы пропустить C/C++-зависимости крипто.
Собрать **дефолтный** набор фич нативно на Windows (BoringSSL через `btls-sys`,
RocksDB, `ring`, `aws-lc-sys`, `pqcrypto-internals`) возможно, но нужен особый
тулчейн: workspace-овый `.cargo/config.toml` в `[env]` форсит флаги GNU-драйвера
(`CC=clang`, `CXX=clang++`, `CXXFLAGS=-include cstdint …`), заточенные под
Linux-раннеры.

Требуется:

- **Visual Studio 2022** с C++-workload (приносит `cmake` + `ninja` в
  `…\Common7\IDE\CommonExtensions\Microsoft\CMake\`).
- **LLVM** (`clang-cl`) — например `winget install LLVM.LLVM`, ставится в
  `C:\Program Files\LLVM\bin`.
- **NASM** (ассемблер x86-64 для BoringSSL / `ring`) — `winget install NASM.NASM`,
  ставится в `%LOCALAPPDATA%\bin\NASM`.

Затем запускайте cargo из оболочки с таким окружением (вставить один раз на сессию
PowerShell либо обернуть в функцию в `$PROFILE`):

```powershell
# 1. Окружение MSVC (INCLUDE/LIB) + bundled ninja/cmake в PATH
$vs = "C:\Program Files\Microsoft Visual Studio\2022\Community"
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null

# 2. clang-cl + NASM в PATH
$env:PATH = "C:\Program Files\LLVM\bin;$env:LOCALAPPDATA\bin\NASM;" + $env:PATH

# 3. Переопределяем заточенные под Linux ручки тулчейна под clang-cl
$env:CC = "clang-cl"; $env:CXX = "clang-cl"   # голый clang давится MSVC-флагом `/arch:AVX2`
$env:CMAKE_GENERATOR = "Ninja"                # генератор VS использует cl.exe / MSBuild
$env:CXXFLAGS = "/FIcstdint /FIcstring"       # форма forced-include для clang-cl вместо `-include` из конфига

cargo build --workspace
cargo clippy --workspace --all-targets
```

Зачем каждая ручка:

- `CC/CXX=clang-cl` — `pqcrypto-internals` передаёт MSVC-флаг `/arch:AVX2`,
  который понимает только драйвер `clang-cl` (голый `clang` падает с ошибкой).
- `CMAKE_GENERATOR=Ninja` — генератор Visual Studio гонит `cl.exe` через MSBuild и
  игнорирует `CC`, а также не принимает clang-флаги. Ninja вызывает `clang-cl`
  напрямую.
- `CXXFLAGS=/FIcstdint /FIcstring` — `clang-cl` не понимает GNU-флаг
  `-include cstdint` из конфига (принимает `cstdint` за отсутствующий входной
  файл, и cmake-конфигурация BoringSSL падает). `/FI` — эквивалентная форма
  forced-include; переопределение переменной окружения заменяет значение из
  конфига на эту сессию.

> Часть example/bin-таргетов помечена `#[cfg(unix)]` и не компилируется под
> `--all-targets` на Windows; ограничьтесь `--lib --tests` (или исключите
> соответствующий крейт), если нужен только линт библиотеки.

---

## Полезные команды для разработки

```bash
# Сборка с проверкой предупреждений
cargo build --workspace 2>&1 | grep -E "warning|error"

# Запуск тестов
cargo test --workspace

# Только unit-тесты (без интеграционных)
cargo test --lib --workspace

# Проверка форматирования
cargo fmt --check

# Clippy
cargo clippy --workspace -- -D warnings

# Документация
cargo doc --workspace --open

# Fuzzing (требует nightly)
cargo +nightly fuzz run fuzz_proto_decode -- -max_total_time=60
```
