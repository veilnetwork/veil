# Архитектура крейтов (целевое состояние)

Цель — разделить монолитный `veilcore` (148 K строк кода) на отдельные
крейты (крейт — это одна Rust-библиотека). Каждый должен независимо
проверяться при аудите, тестироваться и в будущем переезжать в собственный
репозиторий. Пока всё лежит в одном рабочем пространстве (так Cargo называет
набор крейтов, которые собираются вместе); отдельные репозитории появятся
позже.

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

Tier'ы — это слои зависимостей. Крейт одного слоя может зависеть только от
крейтов того же или нижнего слоя — но никогда не от верхнего.

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

Мешают три цикла зависимостей. (Цикл — это когда два модуля лезут друг в
друга, и потому ни один нельзя вынести отдельно.)

1. **cfg ↔ proto** — `cfg::BootstrapPeer` используется
   в `proto::bootstrap_bundle`, а типы `proto::identity_document` —
   при разборе cfg.
2. **cfg ↔ crypto** — `cfg::SignatureAlgorithm` используется в crypto,
   а типы `crypto::session_kdf` — в cfg.
3. **cfg → node** (только в тестах) — тесты `cfg/sovereign_flow.rs`
   ссылаются на `node::identity::verify::verify_identity_document`.

## Порядок миграции (multi-session)

Шаги перечислены в порядке зависимостей. Каждому нужны только
предыдущие шаги, и ничего из последующих.

### Шаг: чистые листья

- **veil-util** — извлекаем `util.rs`. Внутренних зависимостей нет;
  37 вызывающих мест надо обновить заменой `s/crate::util/veil_util/`.

### Шаг: базовые типы

- **veil-types** — новый крейт. Принимает:
  - `cfg::SignatureAlgorithm` (ключ к разрыву цикла crypto/proto)
  - `cfg::NodeId`, `cfg::PeerId`, `cfg::ListenId`, `cfg::LinkId`
  - общие enum'ы ошибок (`cfg::ConfigError`, если получится)

  Это ломает циклы (1) и (2) на уровне типов. Рефакторинг здесь
  механический: каждый модуль, где написано
  `use crate::cfg::SignatureAlgorithm`, переключается на
  `use veil_types::SignatureAlgorithm`.

### Шаг: средний слой

- **veil-proto** — извлекаем `proto/`, как только он начнёт
  зависеть только от veil-types + veil-util.
- **veil-crypto** — извлекаем `crypto/`, как только он начнёт
  зависеть только от veil-types + veil-proto + veil-util.

### Шаг: identity + cfg

- **veil-cfg** — извлекаем то, что осталось от `cfg/` (без типов,
  ушедших в veil-types).
- **veil-identity** — извлекаем:
  - `crypto/identity.rs`
  - `cfg/sovereign_flow.rs`
  - `node/identity/`
  - `proto/identity_document.rs`, `proto/instance_registry.rs`,
    `proto/name_claim_v2.rs`, `proto/mlkem_cert.rs`

  Это крупный шаг: логика identity сейчас размазана по cfg, crypto,
  proto и node.

### Шаг: transport + сетевые примитивы

- **veil-transport** — извлекаем `transport/`, как только два
  его обратных вызова (`TransportHintRegistry`, `Config::from_config`)
  станут передаваться через трейт, а не напрямую по типу.
- **veil-dht** — извлекаем `node/dht/`.
- **veil-mesh** — извлекаем `node/mesh/` + UDP realm.
- **veil-anonymity** — извлекаем `node/anonymity/`.

### Шаг: верхний уровень

- **veil-node** — принимает то, что осталось от `node/`.
- **veil-cli** — извлекаем `cmd/`.

## Журнал выполнения

### Крейт veil-util

`veil-util` извлечён. Добавлен как член рабочего пространства. Все 37
мест вызова продолжают работать через re-export shim — тонкий модуль,
который заново отдаёт перенесённые элементы под их старым путём. Сборка
чистая, тесты зелёные.

### Крейт veil-types

- Создан крейт `veil-types`. Держит `SignatureAlgorithm` и
  `ParseEnumError`.
- 7 модульных тестов перенесено из `cfg/model.rs`.
- Re-export shim `pub use veil_types::{ParseEnumError, SignatureAlgorithm};`
  в `cfg/model.rs` сохраняет все 62 существующих места вызова.
- Циклы cfg ↔ crypto и cfg ↔ proto теперь сломаны НА УРОВНЕ ТИПОВ, но
  только для `SignatureAlgorithm`. Остальные cfg-типы (`NodeId`,
  `ConfigError`) ещё тянут crypto назад; это решают последующие шаги.

### Крейт veil-error

Создан крошечный крейт `veil-error`, который держит `ConfigError` и
`Result` (канонический псевдоним типа). Внешние зависимости
`thiserror`, `base64`, `toml` и `serde_json` перенесены из
veilcore в veil-error. Их версии закреплены под версии veilcore,
чтобы оператор `?` не спотыкался о несовпадение реализаций From-трейта.

`cfg/error.rs` становится re-export shim'ом на 7 строк:

```rust
pub use veil_error::{ConfigError, Result};
```

Все вызывающие места продолжают работать. 6 файлов crypto обновлены на
прямой `use veil_error::{ConfigError, Result}`.

### Разрыв направления proto → crypto

Выбран **Вариант A**: поднять хелперы подписи наверх. Оркестрационный
код перенесли из `proto/` наверх, к его вызывающему слою `node/`:

  - `proto::discovery::{sign_announcement, verify_announcement_signature}`
    →  `node::discovery::announcement_sig::*`
  - `proto::mesh::MeshBeaconPayload::verify_auth` (метод)
    →  `node::mesh::auth::verify_mesh_beacon_auth` (свободная функция)

Боевые вызывающие места (`node::dispatcher::routing`,
`node::dispatcher::discovery`, `node::discovery::directory`,
`node::mesh::beacon`) теперь указывают на новые пути. Сборка и clippy
чистые. Тесты в затронутых областях зелёные (node::mesh 61/61,
node::discovery 33/33, proto:: 516/516).

### Разрыв направления crypto → proto

Три wire-format-константы перенесли в `veil-types`:

  - `ALGO_ML_KEM_768`         (u8)
  - `ML_KEM_768_EK_LEN`       (usize)
  - `CERTIFY_CONTEXT`         (&[u8])

`proto/{prekey_bundle, identity_document}.rs` теперь re-export'ят
их из veil-types, чтобы существующие места вызова продолжали работать.
`crypto/{x3dh, identity}.rs` импортируют их прямо из veil-types.

После разрыва обоих направлений счёт такой:

  - 0 боевых ссылок `crypto → proto`
  - 0 боевых ссылок `proto → crypto`
  - 1 ссылка cfg(test) `proto::identity_contact` → `crypto::compute_node_id`
    (только в тестах — будет обработана при извлечении proto в собственный
    крейт: либо вставкой теста по месту, либо переносом).

Структурный цикл proto ↔ crypto теперь сломан в боевом коде. Оба
крейта готовы к извлечению.

### Финальная зачистка циклов

Четыре точечных переноса убрали все оставшиеся боевые
перекрёстные ссылки между proto/crypto и остальным veilcore:

  1. Base64 serde-хелперы (`hex_array`, `serde_bytes_base64`)
     подняты из `node::dht::kademlia` в `proto::serde_base64` —
     kademlia теперь re-export'ит их, и это соответствует
     естественному расслоению.
  2. Старые хелперы проверки domain-identity
     (`identity_signature_is_valid`, `identity_nonce_meets_difficulty`)
     перенесены из `crypto::identity` в `cfg::identity` — они
     принимают `DomainIdentity` (тип из cfg) и оркеструют
     crypto-примитивы, поэтому им место на вызывающем слое.
     Неиспользуемая обёртка `identity_nonce_has_leading_zero`
     удалена.
  3. Значения по умолчанию для политики PoW (`DEFAULT_POW_DIFFICULTY`
     с учётом cfg(test) и `DEFAULT_POW_TIMEOUT_SECS`) перенесены из
     `identity_policy::IdentityPolicy` в `crypto::pow::score`.
     `identity_policy` теперь re-export'ит их из crypto, разворачивая
     прежнее направление crypto → identity_policy.
  4. Enum'ы `NodeRole` и `DiscoveryMode` (с байтовыми константами
     `role_bits`) перенесены из `cfg::model` в veil-types. Оба —
     чистые данные, и оба потребляются и cfg, и `proto::session`
     (конструктор `CapabilitiesPayload`). `cfg/model.rs` и
     `proto/session.rs` re-export'ят их, чтобы все места вызова
     продолжали работать.

После всех трёх разрывов направлений единственные внутрикрейтовые
ссылки по пути изнутри proto/crypto — в тестовых функциях `#[cfg(test)]`
(кросс-derivation assert'ы) и в doc-комментариях.
В боевом коде ноль зависимостей в любом направлении.

### veil-proto извлечён

`crates/veil-proto/` — теперь самостоятельный член рабочего
пространства, Tier-1.

  - Зависимости: veil-types, veil-util, veil-error;
    внешние: serde, blake3, base64, thiserror, chacha20poly1305,
    ed25519-dalek, rand_core.
  - Перенесено 30 файлов исходников (git записал каждый как
    переименование, ≥ 90% similarity).
  - `crates/veil-proto/src/lib.rs` — однострочный re-export shim
    (`pub use veil_proto::*;`). Он сохраняет каждый существующий
    импорт `crate::proto::X` по cfg/, crypto/, node/, cmd/, sim/.
  - Кросс-валидационный тест `uri_roundtrips_against_a_real_identity_document`
    перемещён в `veilcore/tests/identity_contact_roundtrip.rs` — это
    кросс-слойная интеграция, ей не место внутри proto.
  - `veil-proto`: 515/515 lib-тестов зелёные сами по себе.

### veil-crypto извлечён

`crates/veil-crypto/` — теперь самостоятельный член рабочего
пространства, Tier-1, сосед veil-proto.

  - Зависимости: veil-types, veil-util, veil-error;
    внешние: ed25519-dalek, pqcrypto-falcon, ml-kem, x25519-dalek,
    blake3, hkdf, chacha20poly1305, sha2, zeroize, rand_core,
    base64, ctrlc, thiserror.
  - 11 файлов и подмодуль `pow/` перенесены (≥ 88 % rename similarity).
  - Re-export shim `crates/veil-crypto/src/lib.rs` сохраняет каждое
    существующее место вызова `crate::crypto::X`.
  - Кросс-валидационный тест `node_id_matches_cfg_node_id` перемещён
    в `veilcore/tests/node_id_consistency.rs`.
  - `veil-crypto`: 64/64 lib-тестов зелёные сами по себе.

### Подвох с `cfg(test)` между крейтами — закрыт

И `veil-crypto::pow::score::DEFAULT_POW_DIFFICULTY`, и
`veil-proto::name_claim_v2::required_difficulty` раньше
полагались на обычный `cfg(test)`, чтобы понижать боевую
difficulty (24-28 бит) до тестовой (4-16 бит) — тогда каждый тест
проходит за миллисекунды. Загвоздка: после извлечения `cfg(test)`
срабатывает только внутри крейта, который его задаёт, а не в
тест-профилях крейтов ниже по зависимостям. Так что тесты veilcore
выжгли бы 20 M PoW-попыток на случай — на 18 тестов это минуты
таймаутов.

Решение — cargo-фича `test-low-difficulty` на каждом крейте,
огороженная `cfg(any(test, feature = "test-low-difficulty"))`.
`[dev-dependencies]` в veilcore снова перечисляют оба крейта с
включённой фичей. Cargo объединяет фичи по всей сборке, поэтому
тест-профиль veilcore собирается с пониженной difficulty, а
боевые сборки сохраняют 24/22.

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

Шаги извлечения util, types, error и proto/crypto выполнены.

### Извлечения Tier-2 / Tier-3

Для каждого извлечения ниже перечислены его «trait-инверсии». Это значит,
что кросс-слойную зависимость от конкретного типа veilcore заменили на
трейт, который определяет сам крейт, а veilcore его реализует, — и потому
крейт больше не лезет наверх в veilcore.

  - **veil-transport** ✅ (`crates/veil-transport`) — TCP, QUIC,
    TLS (rustls плюс опционально BoringSSL через `tls-boring`), WebSocket,
    SOCKS5 proxy, Unix-сокеты. Две кросс-слойные зависимости
    инвертированы: `Context::from_config` поднят в `cfg::transport_glue`,
    а `TransportHintRegistry` сведён к трейту `TransportHintSink`.
    34/34 lib-теста зелёные сами по себе.

  - **veil-anonymity** ✅ (`crates/veil-anonymity`) — onion-
    маршрутизация, ячейки фиксированного размера, circuits,
    relay-directory, точки rendezvous, обёртки пакетов. Самая чистая
    цель: единственные её зависимости — `cfg::SignatureAlgorithm` (уже
    в veil-types) и `crypto::*`. 117/117 lib-тестов зелёные сами по себе.

  - **veil-mesh** ✅ (`crates/veil-mesh`) — обнаружение через
    beacon'ы, realm-scoped UDP broadcast, таблица соседей,
    gateway-bridge. Четыре trait-инверсии закрывают кросс-слойные
    зависимости: `BandwidthGuard` (`PerPeerLimiter`), `MeshMetrics`
    (`NodeMetrics`), `BatterySink` (`RttTable`), `NextHopCache`
    (`RouteCache`). `veilcore::node::mesh_glue` собирает
    конкретные адаптеры. 59/59 lib-тестов зелёные сами по себе.

### Остаётся

  - **veil-cfg / veil-identity:** то, что осталось от `cfg/`, и bundle
    суверенной identity (вызывающие места `crypto::identity` в cfg,
    `node::identity/`). Оба ещё переплетены друг с другом и
    с `node::dht`. Чтобы разорвать связку с публикатором в DHT,
    понадобится трейт `DhtPublishSink` в veil-identity.

### veil-dht извлечён

`crates/veil-dht/` — теперь самостоятельный член рабочего
пространства, Tier-3. Держит Kademlia routing и k-bucket, итеративные
lookup'ы, многоуровневое key-value хранилище, кеш резолва транспортов,
LRU-кеш lookup'ов и network-querier.

Четыре кросс-слойные связки с конкретными типами инвертированы через
трейты в `veil_dht::traits`:

  - `FrameRouter` — отправка предварительно закодированных фреймов
    (был `SessionOutbox`). Реализован напрямую на `SessionOutbox`
    в `node::dht_glue`.
  - `RttHint` — упорядочивание контактов с учётом RTT (был
    `RttTable::get(peer).rtt_ms`). `RttHintAdapter` оборачивает
    `Arc<Mutex<RttTable>>`.
  - `CoordinateOracle` — оценка дистанции Vivaldi (был
    `VivaldiCoord::distance_estimate(peer)` плюс кеш по узлам).
    Адаптер `VivaldiOracle` сводит вместе локальную координату
    и кеш по узлам.
  - `DhtMetrics` — счётчики `inc_dht_store` / `inc_dht_lookup`
    (реализованы напрямую на `NodeMetrics`).

`cfg::DhtConfig` зеркалирован в veil-dht как меньший `DhtRuntimeConfig` —
он отбрасывает поля с путями хранения, которые внутренности DHT не
трогают, — а `runtime_config_from(&cfg)` переводит одно в другое
на границе времени выполнения.

`veil-dht`: 109/109 lib-тестов зелёные сами по себе.

### veil-bootstrap + veil-update извлечены

Ещё два Tier-3 крейта. Каждый можно поднять отдельно:

  - **veil-bootstrap** — DNS-TXT seed-записи, подписанные и
    зашифрованные приглашения, загрузка bundle по HTTPS, встроенные
    seeds. Ни одной зависимости вне базового набора; вместе с ним
    в veil-types поднят только `cfg::BootstrapPeer`. 82/82 lib-теста
    зелёные сами по себе.
  - **veil-update** — самообновление (подписанный манифест,
    переключение между несколькими CDN, защита от отката по timestamp,
    атомарная подмена, задача периодической проверки). `cfg::UpdateConfig`
    поднят в veil-types; `NodeLogger` инвертирован через трейт
    `UpdateLogger`. 73/73 lib-теста зелёные сами по себе.

### Остаётся (veil-node + veil-cli)

Оставшийся session runtime (`node/session`, `node/runtime`,
`node/dispatcher`, `node/observability`, `node/abuse`,
`node/routing`, `node/identity`, `node/transfer`, `node/anycast`,
`node/gateway`, …) плюс `cfg/` и `identity_*` становится
veil-node (или дальше делится на veil-cfg +
veil-identity + veil-node). `cmd/` (поверхность CLI)
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

**29 отдельных крейтов извлечено.** Tier 0, 1 и 2 полностью готовы.
Tier 3 покрыт каждой изолированной подсистемой, включая полный
bundle суверенной identity и IPC-сервер.

  - **veil-routing** ✅ — 9 модулей (cache, vivaldi, probe,
    score, pow, loss_tracker, **discovery_forwarder**,
    **discovery_initiator**, **miss_handler**), 94 модульных теста.
    После того как пара discovery приземлилась, `miss_handler`
    последовал за ней через адаптер `FrameBroadcaster` плюс два новых
    трейта — `RoutingLogger` и `RoutingMetrics`. Ограниченный по
    частоте route-flooder больше не лезет в конкретные
    `NodeLogger` / `NodeMetrics` / `SessionTxRegistry` из veilcore.
    Реализация трейта `NextHopCache for RouteCache`
    перенесена из `mesh_glue` veilcore в сам veil-routing
    (чтобы соблюсти orphan-rule). `crates/veil-routing/src/lib.rs`
    теперь чистый re-export shim.

  - **veil-pex** — Peer Exchange: обнаружение соседей через
    случайное блуждание с PoW-challenge и подписанным ответом. Три
    модуля (хелперы верхнего уровня lib, `dispatcher`, `initiator`)
    общим объёмом ~1k LOC, 8 модульных тестов. Три новых
    поверхности trait/type сбрасывают связку с veilcore: `PexLogger`
    (info + warn), реализуемый `NodeLogger`; `PexDispatchOutcome`
    (Response/NoResponse/Violation — строгое подмножество
    `DispatchResult`), транслируемый на границе в
    `veilcore::node::dispatcher::mod`; и `FrameBroadcaster`
    (уже в veil-types), расширенный 4-м методом
    `active_node_ids() -> Vec<[u8; 32]>`, так что PEX может
    перечислять живые сессии для выбора walk-seed и маршрутизации
    ответа, не импортируя `SessionTxRegistry`
    напрямую. `cfg::PexConfig` зеркалирован в veil-types. Все
    4 типа сообщений PEX (Walk/Challenge/Response/Result) покрыты
    на границе. `crates/veil-pex/src/` удалён.

  - **IPC-сервер → veil-ipc + veil-local-transport** —
    модуль `node::ipc` на 3582 строки поднят в два новых крейта.
    `veil-local-transport` (≈1057 LOC, 16 модульных тестов) держит
    обвязку аутентификации по Unix-socket / TCP-loopback / 32-байтному
    токену, общую для admin и IPC; admin по-прежнему обращается
    к ней через `crate::node::local_transport` (re-export shim).
    `veil-ipc` (≈3500 LOC) держит frame-протокол, состояние
    привязки app-id и обработчики debug-capture / transport-hints /
    recursive-query. Три поверхности trait/type расцепляют его от
    veilcore: новый трейт [`IpcMetrics`] (2 метода —
    `inc_ipc_delivery_drops`, `inc_rt_frames_tx`), реализуемый
    в `veil-observability` для `NodeMetrics`;
    [`IpcEndpointError`], который заменяет старый `crate::node::Result`,
    так что крейт остаётся свободен от дерева ошибок veilcore;
    и `Arc<dyn FrameBroadcaster>` вместо
    `Arc<Mutex<SessionTxRegistry>>` (боевой runtime оборачивает его
    через адаптер `SessionTxBroadcaster`). `IpcConfig` зеркалирован
    в `veil_types`. `resolve_ipc_endpoint` и `ipc_anchor_path`
    теперь принимают явный `default_runtime_dir: &Path`, так что
    крейту не нужно лезть обратно в `cfg::runtime_veil_dir()`.

  - **Identity bundle → veil-identity** —
    полный стек суверенной identity поднят из `veilcore::cfg`
    и `veilcore::node::identity` в один Tier-3 крейт. Первый
    подъём (коммит `305e5c2`, ≈2192 LOC) перенёс четыре
    самодостаточных модуля хранения: `master_seed` (BIP39 mnemonic +
    32-байтный ключ), `master_file` (зашифрованный Argon2id формат
    хранения на диске), `master_qr` (оффлайн-кодек QR backup share),
    `instance` (16-байтный `instance_id` на устройство). Ни одной
    veil-внутренней зависимости — wallet-приложения и инструменты
    восстановления могут тянуть только этот срез. 77 модульных тестов.
    Второй подъём (≈9700 LOC) перенёс `cfg::sovereign_flow`
    (`create_identity` / `restore_identity` / `load_identity_sk`) и
    `node::identity::*` (verify, publish, resolver, freshness,
    mlkem_fanout, pair_runtime, pair_transport, sovereign, error,
    integration_tests). Только `publisher_dht.rs`
    (боевой адаптер Kademlia) остался в veilcore, потому
    что зависит от `KademliaService` напрямую.
    `veilcore/src/{cfg/sovereign_flow,node/identity/mod}.rs`
    теперь re-export shim'ы; боевые пути через `cfg::*` и
    `node::identity::*` продолжают работать без изменений.

  - **PendingAckTracker → veil-pending-ack** —
    трекер доставки «хотя бы один раз» (~280 LOC, 3 модульных теста)
    поднят из `veilcore::node::dispatcher::pending_ack`. Ни малейшей
    связности с внутренностями dispatcher'а — зависит только от констант
    `veil_proto::budget` — поэтому стоит самостоятельным крейтом
    и разблокирует предстоящее извлечение veil-ipc, чьи
    обработчики запросов вызывают `register` / `ack` / `tick`
    напрямую. `crates/veil-dispatcher/src/pending_ack.rs`
    теперь чистый re-export shim.

  - **TransportHintRegistry → veil-transport** —
    счётчик результатов подключения по схемам (~200 LOC) поднят из
    `veilcore::node::transport_hints` в
    `veil-transport::hint_registry`. Структура уже реализовывала
    трейт `TransportHintSink` (тоже определённый в veil-transport),
    так что, поместив их рядом, убираем лишнюю прослойку из-за orphan-rule
    и закрываем одну из остаточных утечек конкретного типа veilcore
    в IPC-сервер. `crates/veil-transport/src/hint_registry.rs` теперь
    чистый re-export shim. Все 5 модульных тестов и все 39 тестов
    veil-transport по-прежнему проходят. Это предусловие для
    предстоящего извлечения veil-ipc.

  - **veil-proxy** — SOCKS5 ingress, exit-proxy и
    коннектор veil-stream: три модуля (`socks5`, `exit`,
    `veil_connector`) общим объёмом ~1.6k LOC, 18 модульных тестов.
    У `socks5.rs` было **ноль** зависимостей от veilcore (чистый
    протокол RFC1928 плюс обвязка сокетов). `exit.rs` нуждался только
    в `cfg::NodeRole` (уже в veil-types) плюс одиночный вызов
    метрики `inc_exit_proxy_dest_denied`, который стал новым трейтом
    `ProxyMetrics`. `veil_connector.rs` использовал
    `Arc<Mutex<SessionTxRegistry>>` для APP_OPEN / APP_DATA /
    APP_CLOSE — это заменено на `Arc<dyn FrameBroadcaster>` от и до.
    `crates/veil-node-runtime/src/proxy/` теперь re-export shim плюс
    integration glue `tasks.rs`. (Эта обвязка конструирует адаптеры
    `SessionTxBroadcaster` из конкретных типов runtime и оставлена на
    стороне veilcore, потому что ей нужны `cfg::Config`,
    `FrameDispatcher.role`, `AppEndpointRegistry` и так далее.) Тяжёлые
    end-to-end тесты отложены до integration-suite veilcore;
    отдельная тестовая поверхность использует in-process
    mock `RecordingBroadcaster` для покрытия на уровне трейтов.

То, что осталось — node runtime, session, dispatcher, identity, cmd,
sim и cfg-engine, плюс Tier-3 листья (ipc, gateway-task), — естественно
консолидируется в `veil-node` и `veil-cli` в финальной фазе.

Общее количество trait-инверсий — **17** (TransportHintSink,
BandwidthGuard, MeshMetrics, BatterySink, NextHopCache,
FrameRouter, RttHint, CoordinateOracle, DhtMetrics, UpdateLogger,
AbuseLogger, AppMetrics, **FrameBroadcaster** [расширен
`active_node_ids`], **RoutingLogger**, **RoutingMetrics**,
**PexLogger**, **ProxyMetrics**). `FrameBroadcaster` живёт
в `veil-types`; его боевой адаптер
`node::session_glue::SessionTxBroadcaster` оборачивает
`Arc<Mutex<SessionTxRegistry>>` и от и до проверен тестом
`veilcore/tests/frame_broadcaster_adapter.rs`. `RoutingLogger` и
`RoutingMetrics` живут рядом со своим потребителем
в `veil-routing`, а `PexLogger` — точно так же в `veil-pex`.
Все кросс-крейтовые реализации трейтов для `NodeMetrics` / `NodeLogger`
консолидированы в `veil-observability`, что держит их в согласии
с orphan-rule.

Общее количество config-зеркал — 8 enum'ов и struct'ов
в veil-types (SignatureAlgorithm, NodeRole, DiscoveryMode,
BootstrapPeer, UpdateConfig, NatConfig, log/metrics enums,
**PexConfig**) плюс DhtRuntimeConfig в veil-dht.

## Почему важна инкрементальность

148 K строк кода. Каждый разрыв цикла затрагивает десятки-сотни файлов.
Риск тонких регрессий в поведении при массовом редактировании
высок. Тестирование на границе каждой фазы — единственный способ
держать планку качества. Делать всё инкрементально — по одной фазе
за сессию — это ответственный путь.

## Почему нельзя «просто сделать все фазы за раз»

148 K строк кода. Циклы между cfg, proto и crypto требуют разрыва
ДО извлечения — для этого `SignatureAlgorithm` и переносят в общий
types-крейт. Каждый разрыв цикла затрагивает десятки-сотни файлов.
Риск тонких регрессий в поведении при массовом редактировании высок,
и тестирование на границе каждой фазы — единственный способ держать
планку качества. Делать всё инкрементально — по одной фазе за сессию —
это ответственный путь.
