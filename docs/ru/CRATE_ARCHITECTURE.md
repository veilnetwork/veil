# Архитектура крейтов (целевое состояние)

Цель: разделить монолитный `veilcore` (148 K LOC) на сфокусированные
крейты, каждый из которых независимо аудируем / тестируем / в будущем
извлекаем в собственный репозиторий. Workspace пока остаётся здесь;
per-crate репозитории — потом.

## Целевая структура

```
veil/                              (workspace root)
├── crates/
│   ├── veil-util                  # Tier 0: макросы, atomic_write, hex
│   ├── veil-types                 # Tier 0: SignatureAlgorithm, NodeId,
│   │                                 #         PeerId, error enums
│   ├── veil-proto                 # Tier 1: wire-форматы, кодеки
│   ├── veil-crypto                # Tier 1: Ed25519/Falcon/X25519/AEAD
│   ├── veil-cfg                   # Tier 2: схема конфига + валидация
│   ├── veil-identity              # Tier 2: суверенная identity, делегирование
│   ├── veil-transport             # Tier 2: TLS, TCP, QUIC, WS, MeshUDP
│   ├── veil-dht                   # Tier 3: Kademlia routing
│   ├── veil-mesh                  # Tier 3: local-LAN UDP realm
│   ├── veil-anonymity             # Tier 3: onion + circuits + rendezvous
│   ├── veil-node                  # Tier 4: session runtime, dispatcher
│   └── veil-cli                   # Tier 5: CLI-бинарник
├── veilclient                     # существующий client SDK
└── ...
```

Tier'ы — это слои зависимостей: tier может зависеть только от равного
или нижестоящего tier'а.

## Текущее состояние (до разделения)

```
veilcore (монолит; 148 K LOC)
├── util.rs                # настоящий лист, 0 внутренних зависимостей
├── transport/             # лист, но имеет 2 callback'а в node/cfg
├── cfg/                   # «кухонная раковина»: зависит от crypto, proto, util,
│                          #                      + test-only зависимости на node
├── crypto/                # циклы с cfg + proto
├── proto/                 # циклы с cfg + crypto
├── identity_ops.rs        # зависит от cfg, crypto
├── identity_policy.rs     # зависит от cfg
├── node/                  # зависит от всего выше
├── cmd/                   # зависит от всего (CLI)
└── sim/                   # test-only, зависит от cfg + node
```

Обнаруженные циклы:

1. **cfg ↔ proto** — `cfg::BootstrapPeer` используется
   в `proto::bootstrap_bundle`; типы `proto::identity_document` —
   при парсинге cfg.
2. **cfg ↔ crypto** — `cfg::SignatureAlgorithm` используется crypto;
   типы `crypto::session_kdf` — в cfg.
3. **cfg → node** (test-only) — тесты `cfg/sovereign_flow.rs`
   ссылаются на `node::identity::verify::verify_identity_document`.

## Порядок миграции (multi-session)

Перечислены в порядке зависимостей — каждый шаг требует выполнения
только предыдущих.

### Шаг: чистые листья

- **veil-util** — извлекаем `util.rs`. Ноль внутренних зависимостей;
  37 caller'ов обновляются `s/crate::util/veil_util/`.

### Шаг: foundational types

- **veil-types** — новый крейт; принимает:
  - `cfg::SignatureAlgorithm` (разрыватель цикла crypto/proto)
  - `cfg::NodeId`, `cfg::PeerId`, `cfg::ListenId`, `cfg::LinkId`
  - общие error-enum'ы (`cfg::ConfigError`, если viable)

  Это ломает циклы (1) и (2) на уровне типов. Рефакторинг: каждый
  модуль, где написано `use crate::cfg::SignatureAlgorithm`,
  переключается на `use veil_types::SignatureAlgorithm`.

### Шаг: средний tier

- **veil-proto** — извлекаем `proto/`, как только он начнёт
  зависеть только от veil-types + veil-util.
- **veil-crypto** — извлекаем `crypto/`, как только он начнёт
  зависеть только от veil-types + veil-proto + veil-util.

### Шаг: identity + cfg

- **veil-cfg** — извлекаем остаточный `cfg/` (без типов, ушедших
  в veil-types).
- **veil-identity** — извлекаем:
  - `crypto/identity.rs`
  - `cfg/sovereign_flow.rs`
  - `node/identity/`
  - `proto/identity_document.rs`, `proto/instance_registry.rs`,
    `proto/name_claim_v2.rs`, `proto/mlkem_cert.rs`

  Существенный шаг, потому что identity-логика сейчас размазана
  по cfg + crypto + proto + node.

### Шаг: transport + сетевые примитивы

- **veil-transport** — извлекаем `transport/`, как только два
  его callback'а (`TransportHintRegistry`, `Config::from_config`)
  станут trait-инъецированными вместо прямой типизации.
- **veil-dht** — извлекаем `node/dht/`.
- **veil-mesh** — извлекаем `node/mesh/` + UDP realm.
- **veil-anonymity** — извлекаем `node/anonymity/`.

### Шаг: верхний уровень

- **veil-node** — принимает остаточный `node/`.
- **veil-cli** — извлекаем `cmd/`.

## Журнал выполнения

### Util-крейт

- `veil-util` извлечён. Workspace member добавлен; 37 call-site'ов
  сохранены через re-export shim; сборка чистая; тесты зелёные.

### Types-крейт

- Создан крейт `veil-types`. Хостит `SignatureAlgorithm` +
  `ParseEnumError`.
- 7 unit-тестов перенесено из `cfg/model.rs`.
- Re-export shim `pub use veil_types::{ParseEnumError, SignatureAlgorithm};`
  в `cfg/model.rs` сохраняет все 62 существующих call-site'а.
- Циклы cfg ↔ crypto и cfg ↔ proto теперь сломаны НА УРОВНЕ ТИПОВ
  именно для `SignatureAlgorithm`. Остальные cfg-типы (`NodeId`,
  `ConfigError`) ещё создают обратные зависимости для crypto;
  последующие шаги это адресуют.

### Error-крейт

Создан крошечный крейт `veil-error`, хостящий `ConfigError` +
`Result` (канонический type alias). Внешние зависимости
`thiserror` + `base64` + `toml` + `serde_json` перенесены из
veilcore в veil-error (версии подогнаны под veilcore,
чтобы оператор `?` не ломался на несовпадениях From-trait'ов).

`cfg/error.rs` становится re-export shim'ом на 7 строк:

```rust
pub use veil_error::{ConfigError, Result};
```

Все caller'ы продолжают работать. 6 файлов crypto обновлены на
прямой `use veil_error::{ConfigError, Result}`.

### Разрыв направления proto → crypto

Выбран **Вариант A** (поднять sign-helper'ы). Перенесли
оркестрационный код из `proto/` к caller-слою `node/`:

  - `proto::discovery::{sign_announcement, verify_announcement_signature}`
    →  `node::discovery::announcement_sig::*`
  - `proto::mesh::MeshBeaconPayload::verify_auth` (метод)
    →  `node::mesh::auth::verify_mesh_beacon_auth` (свободная функция)

Production-caller'ы (`node::dispatcher::routing`,
`node::dispatcher::discovery`, `node::discovery::directory`,
`node::mesh::beacon`) обновлены на новые пути. Сборка/clippy
чистые; тесты затронутых областей зелёные (node::mesh 61/61,
node::discovery 33/33, proto:: 516/516).

### Разрыв направления crypto → proto

Перенесли три wire-format-константы в `veil-types`:

  - `ALGO_ML_KEM_768`         (u8)
  - `ML_KEM_768_EK_LEN`       (usize)
  - `CERTIFY_CONTEXT`         (&[u8])

`proto/{prekey_bundle, identity_document}.rs` теперь re-export'ят
их из veil-types для сохранения существующих call-site'ов.
`crypto/{x3dh, identity}.rs` импортируют напрямую из veil-types.

После разрыва обоих направлений:

  - 0 production-ссылок `crypto → proto`
  - 0 production-ссылок `proto → crypto`
  - 1 cfg(test)-ссылка `proto::identity_contact` → `crypto::compute_node_id`
    (test-only — будет обработана при извлечении proto в собственный
    крейт либо инлайном теста, либо переносом).

Структурный цикл proto ↔ crypto теперь сломан в production. Оба
крейта готовы к извлечению.

### Финальная зачистка циклов

Четыре точечных переноса убрали все оставшиеся production
cross-ref'ы между proto/crypto и остальным veilcore:

  1. Base64 serde-хелперы (`hex_array`, `serde_bytes_base64`)
     подняты из `node::dht::kademlia` в `proto::serde_base64` —
     kademlia теперь re-export'ит их, соответствуя естественному
     наслоению.
  2. Legacy-хелперы валидации domain-identity
     (`identity_signature_is_valid`, `identity_nonce_meets_difficulty`)
     перенесены из `crypto::identity` в `cfg::identity` — они
     принимают `DomainIdentity` (cfg-тип) и оркеструют
     crypto-примитивы, поэтому им место на caller-слое.
     Неиспользуемая обёртка `identity_nonce_has_leading_zero`
     удалена.
  3. Дефолты PoW-политики (`DEFAULT_POW_DIFFICULTY` с поддержкой
     cfg(test), `DEFAULT_POW_TIMEOUT_SECS`) перенесены из
     `identity_policy::IdentityPolicy` в `crypto::pow::score`.
     `identity_policy` теперь re-export'ит из crypto, разворачивая
     прежнее направление crypto → identity_policy.
  4. Enum'ы `NodeRole` + `DiscoveryMode` (с байтовыми константами
     `role_bits`) перенесены из `cfg::model` в veil-types. Оба —
     pure data и потребляются и cfg, и `proto::session`
     (конструктор `CapabilitiesPayload`). `cfg/model.rs` и
     `proto/session.rs` re-export'ят для сохранения всех call-site'ов.

После всех трёх разрывов направлений единственные оставшиеся
crate-internal path-ссылки изнутри proto/crypto — в `#[cfg(test)]`
тестовых функциях (кросс-derivation assert'ы) и в doc-комментариях.
В production-коде ноль зависимостей в любом направлении.

### veil-proto извлечён

`crates/veil-proto/` — теперь самостоятельный workspace member
Tier-1.

  - Зависимости: veil-types, veil-util, veil-error;
    внешние: serde, blake3, base64, thiserror, chacha20poly1305,
    ed25519-dalek, rand_core.
  - Перенесено 30 source-файлов (git rename ≥ 90% similarity на
    каждый файл).
  - `crates/veil-proto/src/lib.rs` — однострочный re-export shim
    (`pub use veil_proto::*;`), сохраняющий каждый существующий
    импорт `crate::proto::X` по cfg/, crypto/, node/, cmd/, sim/.
  - Cross-validation тест `uri_roundtrips_against_a_real_identity_document`
    перемещён в `veilcore/tests/identity_contact_roundtrip.rs`
    (кросс-слойная интеграция, не место внутри proto).
  - `veil-proto`: 515/515 lib-тестов зелёные standalone.

### veil-crypto извлечён

`crates/veil-crypto/` — теперь самостоятельный workspace member
Tier-1, sibling veil-proto.

  - Зависимости: veil-types, veil-util, veil-error;
    внешние: ed25519-dalek, pqcrypto-falcon, ml-kem, x25519-dalek,
    blake3, hkdf, chacha20poly1305, sha2, zeroize, rand_core,
    base64, ctrlc, thiserror.
  - 11 файлов + submodule `pow/` перенесены (≥ 88 % rename similarity).
  - Re-export shim `crates/veil-crypto/src/lib.rs` сохраняет каждый
    существующий call-site `crate::crypto::X`.
  - Cross-validation тест `node_id_matches_cfg_node_id` перемещён
    в `veilcore/tests/node_id_consistency.rs`.
  - `veil-crypto`: 64/64 lib-тестов зелёные standalone.

### Гочча с кросс-крейтовым `cfg(test)` — закрыта

Оба `veil-crypto::pow::score::DEFAULT_POW_DIFFICULTY` и
`veil-proto::name_claim_v2::required_difficulty` ранее
использовали обычный `cfg(test)`, чтобы понижать production
difficulty (24-28 бит) до тестовой (4-16 бит) для прогонов
ms-per-test. После извлечения `cfg(test)` срабатывает только
внутри производящего крейта, не в downstream test-профилях, так
что тесты veilcore выжгли бы 20 M PoW-попыток на кейс
(× 18 тестов = минуты таймаутов).

Фикс: cargo-фича `test-low-difficulty` на каждом крейте,
огороженная `cfg(any(test, feature = "test-low-difficulty"))`.
`[dev-dependencies]` в veilcore перечисляют оба крейта с
включённой фичей; feature-unification у cargo приводит к тому, что
test-профиль veilcore собирается с low difficulty, а
production-сборки сохраняют 24/22.

### Где мы стоим

```
crates/
├── veil-error      ✅ Tier 0 (ConfigError + Result)
├── veil-types      ✅ Tier 0 (SignatureAlgorithm, NodeRole, DiscoveryMode,
│                                role_bits, ALGO_ML_KEM_768, ML_KEM_768_EK_LEN,
│                                CERTIFY_CONTEXT, ParseEnumError)
├── veil-util       ✅ Tier 0 (atomic_write, hex, retry, leading_zero_bits)
├── veil-adaptive   ✅ Tier 0 (формулы параметров от размера сети:
│                                AdaptiveParams + estimate_network_size; 15 тестов)
├── veil-proto      ✅ Tier 1 (wire-форматы, кодеки; 515 unit-тестов)
└── veil-crypto     ✅ Tier 1 (подписи, KEM, AEAD, PoW; 64 unit-теста)
veilcore/           (cfg за вычетом adaptive, identity_*, node/*, cmd/*,
                       sim/*, transport/*)
```

Шаги извлечения util, types, error и proto/crypto — выполнены.

### Извлечения Tier-2 / Tier-3

  - **veil-transport** ✅ (`crates/veil-transport`) — TCP, QUIC,
    TLS (rustls + опционально BoringSSL через `tls-boring`), WebSocket,
    SOCKS5 proxy, Unix-сокеты. Две кросс-слойные зависимости
    инвертированы: `Context::from_config` поднято в `cfg::transport_glue`,
    `TransportHintRegistry` редуцирован до trait'а `TransportHintSink`.
    34/34 lib-теста зелёные standalone.

  - **veil-anonymity** ✅ (`crates/veil-anonymity`) — onion-
    маршрутизация, фиксированного размера cells, circuits,
    relay-directory, rendezvous-точки, packet-обёртки. Самая чистая
    цель — только `cfg::SignatureAlgorithm` (уже в veil-types)
    и зависимости от `crypto::*`. 117/117 lib-тестов зелёные standalone.

  - **veil-mesh** ✅ (`crates/veil-mesh`) — discovery через
    beacon'ы, realm-scoped UDP broadcast, таблица соседей,
    gateway-bridge. Четыре trait-инверсии для кросс-слойных
    зависимостей: `BandwidthGuard` (`PerPeerLimiter`), `MeshMetrics`
    (`NodeMetrics`), `BatterySink` (`RttTable`), `NextHopCache`
    (`RouteCache`). `veilcore::node::mesh_glue` собирает
    конкретные адаптеры. 59/59 lib-тестов зелёные standalone.

### Остаётся

  - **veil-cfg / veil-identity:** остаточный `cfg/` и bundle
    sovereign-identity (caller'ы `crypto::identity` в cfg,
    `node::identity/`). Оба ещё переплетены друг с другом и
    с `node::dht`; понадобится trait `DhtPublishSink` в
    veil-identity, чтобы сломать связку с dht-publisher'ом.

### veil-dht извлечён

`crates/veil-dht/` — теперь самостоятельный workspace member
Tier-3: Kademlia routing + k-bucket, итеративные lookup'ы,
многоуровневое key-value хранилище, кеш резолва транспортов,
LRU-кеш lookup'ов, network-querier.

Четыре кросс-слойных concrete-type связки инвертированы через
trait'ы в `veil_dht::traits`:

  - `FrameRouter` — отправка предварительно закодированных фреймов
    (был `SessionOutbox`). Реализован напрямую на `SessionOutbox`
    в `node::dht_glue`.
  - `RttHint` — RTT-зависимая упорядоченность контактов (был
    `RttTable::get(peer).rtt_ms`). `RttHintAdapter` оборачивает
    `Arc<Mutex<RttTable>>`.
  - `CoordinateOracle` — оценка Vivaldi-дистанции (был
    `VivaldiCoord::distance_estimate(peer)` + per-peer кеш).
    Адаптер `VivaldiOracle` комбинирует локальную координату
    и per-peer кеш.
  - `DhtMetrics` — счётчики `inc_dht_store` / `inc_dht_lookup`
    (реализованы напрямую на `NodeMetrics`).

`cfg::DhtConfig` зеркалирован как меньший `DhtRuntimeConfig`
в veil-dht (отбрасывает persistence-path поля, которые
внутренности DHT не трогают); `runtime_config_from(&cfg)` делает
конвертацию на runtime-границах.

`veil-dht`: 109/109 lib-тестов зелёные standalone.

### veil-bootstrap + veil-update извлечены

Ещё два Tier-3 крейта, оба независимо bootstrap'аемые:

  - **veil-bootstrap** — DNS-TXT seed-записи, подписанные/
    зашифрованные invite'ы, HTTPS bundle-fetch, builtin seeds.
    Ноль out-of-base зависимостей; вместе с ним в veil-types
    поднят только `cfg::BootstrapPeer`. 82/82 lib-теста зелёные
    standalone.
  - **veil-update** — self-update (подписанный манифест,
    multi-CDN failover, anti-downgrade timestamp, атомарный swap,
    периодическая проверка). `cfg::UpdateConfig` поднят в
    veil-types; `NodeLogger` инвертирован через trait
    `UpdateLogger`. 73/73 lib-теста зелёные standalone.

### Остаётся (veil-node + veil-cli)

Остаточный session runtime (`node/session`, `node/runtime`,
`node/dispatcher`, `node/observability`, `node/abuse`,
`node/routing`, `node/identity`, `node/transfer`, `node/anycast`,
`node/gateway`, …) плюс `cfg/` и `identity_*` становится
veil-node (или дальше разделяется на veil-cfg +
veil-identity + veil-node). `cmd/` (CLI-поверхность)
становится veil-cli.

Оценка времени: 1-3 будущих сессии на оставшуюся миграцию.

### Где мы стоим

```
crates/                                                         тесты
├── veil-error          ✅ Tier 0                              —
├── veil-types          ✅ Tier 0  (+ BootstrapPeer, UpdateConfig,
│                                       NatConfig, log/metrics enums)    8
├── veil-util           ✅ Tier 0                              4
├── veil-memory         ✅ Tier 0                              4
├── veil-proto          ✅ Tier 1                            515
├── veil-crypto         ✅ Tier 1                             64
├── veil-transport      ✅ Tier 2  (+ TransportHintRegistry)   39
├── veil-transfer       ✅ Tier 2                              6
├── veil-abuse          ✅ Tier 3                             81
├── veil-anonymity      ✅ Tier 3                            117
├── veil-anycast        ✅ Tier 3                              5
├── veil-app            ✅ Tier 3                             37
├── veil-bootstrap      ✅ Tier 3                             82
├── veil-dht            ✅ Tier 3                            109
├── veil-discovery      ✅ Tier 3                             32
├── veil-e2e            ✅ Tier 3                              9
├── veil-gateway        ✅ Tier 3                             16
├── veil-identity       ✅ Tier 3 (sovereign identity bundle) 77
├── veil-ipc            ✅ Tier 3 (IPC-сервер, trait IpcMetrics)  —
├── veil-local-transport ✅ Tier 2 (Unix/TCP+token plumbing)  16
├── veil-mesh           ✅ Tier 3                             59
├── veil-nat            ✅ Tier 3                             26
├── veil-dispatcher-state ✅ Tier 3 (PendingRecursive/CaptureEvent/DiagEvent)  —
├── veil-observability  ✅ Tier 3 (хаб trait'ов для orphan-rule)   6
├── veil-pending-ack    ✅ Tier 3 (retransmit FSM)               3
├── veil-pex            ✅ Tier 3                              8
├── veil-proxy          ✅ Tier 3                             18
└── veil-update         ✅ Tier 3                             73
veilcore/               cfg, identity_*, cmd, sim, node/{session,
                           runtime, dispatcher, identity,
                           proxy/tasks (только integration glue),
                           ipc, gateway, admin, …}
```

**29 отдельных крейтов извлечено.** Tier 0/1/2 полностью готовы.
Tier 3 покрыт каждой изолированной подсистемой, включая полный
bundle суверенной identity и IPC-сервер.

  - **veil-routing** ✅ — 9 модулей (cache, vivaldi, probe,
    score, pow, loss_tracker, **discovery_forwarder**,
    **discovery_initiator**, **miss_handler**) — 94 unit-теста.
    После того как discovery-пара приземлилась, `miss_handler`
    последовал через адаптер `FrameBroadcaster` плюс две новые
    trait-поверхности — `RoutingLogger` и `RoutingMetrics` — так
    что rate-limit'нутый route-flooder больше не лезет в
    конкретные `NodeLogger` / `NodeMetrics` / `SessionTxRegistry`
    veilcore. Trait-impl `NextHopCache for RouteCache`
    перенесён из `mesh_glue` veilcore в сам veil-routing
    (orphan-rule fix). `crates/veil-routing/src/mod.rs`
    теперь чистый re-export shim.

  - **veil-pex** — Peer Exchange: discovery соседей через
    random-walk с PoW-challenge + подписанным response. Три модуля
    (lib top-level хелперы, `dispatcher`, `initiator`) общим
    объёмом ~1k LOC, 8 unit-тестов. Три новых поверхности
    trait/type сбрасывают связку с veilcore: `PexLogger`
    (info + warn), реализуемый `NodeLogger`; `PexDispatchOutcome`
    (Response/NoResponse/Violation — строгое подмножество
    `DispatchResult`), транслируемый на границе в
    `veilcore::node::dispatcher::mod`; и `FrameBroadcaster`
    (уже в veil-types) расширен 4-м методом
    `active_node_ids() -> Vec<[u8; 32]>`, так что PEX может
    перечислять живые сессии для выбора walk-seed / маршрутизации
    ответа без необходимости импортировать `SessionTxRegistry`
    конкретно. `cfg::PexConfig` зеркалирован в veil-types. Все
    4 типа сообщений PEX (Walk/Challenge/Response/Result) покрыты
    границей. `crates/veil-pex/src/` удалён.

  - **IPC-сервер → veil-ipc + veil-local-transport** —
    модуль `node::ipc` на 3582 строки поднят в два новых крейта.
    `veil-local-transport` (≈1057 LOC, 16 unit-тестов) хостит
    plumbing аутентификации Unix-socket / TCP-loopback / 32-байт
    токеном, общий для admin и IPC; admin по-прежнему ссылается
    на него через `crate::node::local_transport` (re-export shim).
    `veil-ipc` (≈3500 LOC) держит frame-протокол, состояние
    привязки app-id и handler'ы debug-capture / transport-hints /
    recursive-query. Три trait/type-поверхности расцепляют от
    veilcore: новый trait [`IpcMetrics`] (2 метода —
    `inc_ipc_delivery_drops`, `inc_rt_frames_tx`), реализуемый
    в `veil-observability` для `NodeMetrics`;
    [`IpcEndpointError`] заменяет старый `crate::node::Result`,
    так что крейт остаётся свободен от error-дерева veilcore;
    и `Arc<dyn FrameBroadcaster>` вместо
    `Arc<Mutex<SessionTxRegistry>>` (production runtime оборачивает
    через адаптер `SessionTxBroadcaster`). `IpcConfig` зеркалирован
    в `veil_types`. `resolve_ipc_endpoint` / `ipc_anchor_path`
    теперь принимают явный `default_runtime_dir: &Path`, так что
    крейту не нужно лезть обратно в `cfg::runtime_veil_dir()`.

  - **Identity bundle → veil-identity** —
    полный стек суверенной identity поднят из `veilcore::cfg`
    и `veilcore::node::identity` в один Tier-3 крейт. Первый
    подъём (коммит `305e5c2`, ≈2192 LOC): четыре самодостаточных
    persistence-модуля — `master_seed` (BIP39 mnemonic + 32-байт
    ключ), `master_file` (Argon2id-шифрованный at-rest формат),
    `master_qr` (оффлайн QR backup share codec), `instance`
    (per-device 16-байт `instance_id`). Ноль veil-внутренних
    зависимостей — wallet-приложения и recovery-tooling могут
    тянуть только этот срез. 77 unit-тестов. Второй подъём
    (≈9700 LOC): `cfg::sovereign_flow` (`create_identity` /
    `restore_identity` / `load_identity_sk`) и
    `node::identity::*` (verify, publish, resolver, freshness,
    mlkem_fanout, pair_runtime, pair_transport, sovereign, error,
    integration_tests) — всё перенесено. Только `publisher_dht.rs`
    (production-адаптер Kademlia) остался в veilcore, потому
    что зависит от `KademliaService` напрямую.
    `veilcore/src/{cfg/sovereign_flow,node/identity/mod}.rs`
    теперь re-export shim'ы; production-пути через `cfg::*` и
    `node::identity::*` продолжают работать без изменений.

  - **PendingAckTracker → veil-pending-ack** —
    трекер at-least-once доставки (~280 LOC, 3 unit-теста) поднят
    из `veilcore::node::dispatcher::pending_ack`. Ноль связности
    с внутренностями dispatcher'а — зависит только от констант
    `veil_proto::budget` — поэтому стоит самостоятельным крейтом
    и разблокирует предстоящее извлечение veil-ipc, чьи
    request-handler'ы вызывают `register` / `ack` / `tick`
    напрямую. `crates/veil-dispatcher/src/pending_ack.rs`
    теперь чистый re-export shim.

  - **TransportHintRegistry → veil-transport** —
    per-scheme счётчик connect-outcome (~200 LOC) поднят из
    `veilcore::node::transport_hints` в
    `veil-transport::hint_registry`. Структура уже реализовывала
    trait `TransportHintSink` (тоже определённый в veil-transport),
    так что co-locating обоих убирает orphan-rule indirection и
    устраняет одну из остаточных утечек концретных типов veilcore
    в IPC-сервере. `crates/veil-transport/src/hint_registry.rs` теперь
    чистый re-export shim. Все 5 unit-тестов + 39 общих тестов
    veil-transport по-прежнему проходят. Предусловие для
    предстоящего извлечения veil-ipc.

  - **veil-proxy** — SOCKS5 ingress + exit-proxy +
    veil-stream connector: три модуля (`socks5`, `exit`,
    `veil_connector`) общим объёмом ~1.6k LOC, 18 unit-тестов.
    У `socks5.rs` было **ноль** зависимостей от veilcore (чистый
    RFC1928 протокол + socket plumbing). `exit.rs` нуждался только
    в `cfg::NodeRole` (уже в veil-types) плюс одиночный вызов
    метрики `inc_exit_proxy_dest_denied` → новый trait
    `ProxyMetrics`. `veil_connector.rs` использовал
    `Arc<Mutex<SessionTxRegistry>>` для APP_OPEN / APP_DATA /
    APP_CLOSE — заменено на `Arc<dyn FrameBroadcaster>` end-to-end.
    `crates/veil-node-runtime/src/proxy/` теперь re-export shim плюс
    integration glue `tasks.rs` (конструирует адаптеры
    `SessionTxBroadcaster` из конкретов runtime — оставлен на
    стороне veilcore, потому что ему нужны `cfg::Config`,
    `FrameDispatcher.role`, `AppEndpointRegistry` и т.д.). Тяжёлые
    end-to-end тесты отложены до integration-suite veilcore;
    standalone test-поверхность использует in-process
    `RecordingBroadcaster` mock для trait-уровня покрытия.

Остаточное = node runtime / session / dispatcher / identity / cmd /
sim / cfg-engine + Tier-3 листья (ipc, gateway-task) → естественно
консолидируется в `veil-node` + `veil-cli` в финальной фазе.

Общее количество trait-инверсий: **17** (TransportHintSink,
BandwidthGuard, MeshMetrics, BatterySink, NextHopCache,
FrameRouter, RttHint, CoordinateOracle, DhtMetrics, UpdateLogger,
AbuseLogger, AppMetrics, **FrameBroadcaster** [расширен
`active_node_ids`], **RoutingLogger**, **RoutingMetrics**,
**PexLogger**, **ProxyMetrics**). `FrameBroadcaster` живёт
в `veil-types` (production-адаптер
`node::session_glue::SessionTxBroadcaster` оборачивает
`Arc<Mutex<SessionTxRegistry>>`, end-to-end проверено
`veilcore/tests/frame_broadcaster_adapter.rs`). `RoutingLogger`,
`RoutingMetrics` живут рядом со своим потребителем
в `veil-routing`; `PexLogger` — аналогично в `veil-pex`.
Все кросс-крейтовые trait-impl для `NodeMetrics` / `NodeLogger`
консолидированы в `veil-observability` (соответствие
orphan-rule).

Общее количество config-зеркал: 8 enum'ов/struct'ов
в veil-types (SignatureAlgorithm, NodeRole, DiscoveryMode,
BootstrapPeer, UpdateConfig, NatConfig, log/metrics enums,
**PexConfig**) + DhtRuntimeConfig в veil-dht.

## Почему инкрементальность важна

148 K LOC. Каждый разрыв цикла затрагивает десятки-сотни файлов.
Риск тонких поведенческих регрессий при массовом редактировании
высок. Тестирование на границе каждой фазы — единственный способ
держать качественную планку. Делать инкрементально — одна фаза
за сессию — это ответственный путь.

## Почему нельзя «просто сделать все фазы за раз»

148 K LOC. Циклы между cfg + proto + crypto требуют разрыва ДО
извлечения (перенести `SignatureAlgorithm` в общий types-крейт).
Каждый разрыв цикла затрагивает десятки-сотни файлов. Риск тонких
поведенческих регрессий при массовом редактировании высок;
тестирование на границе каждой фазы — единственный способ держать
качественную планку. Делать инкрементально — одна фаза за сессию —
это ответственный путь.
