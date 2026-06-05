# Messenger: руководство разработчика

Как построить мессенджер в стиле Signal (или любое приложение,
которому нужна суверенная identity + async-доставка) поверх veil.

Этот документ указывает на API; сигнатуры — в связанных source-файлах,
а user-visible поведение — в сопутствующих документах.

- [`identity-model.md`](identity-model.md) — спецификация протокола.
- [`multi-device.md`](multi-device.md) — разделение режимов LB и
  messenger.
- [`recovery.md`](recovery.md) — user-visible flow восстановления.
- [`opsec-user-guide.md`](opsec-user-guide.md) — раздавайте своим
  пользователям.

---

## 1. Что veil даёт, а что не даёт

**Даёт**:

- Суверенную identity (`identity_id` стабилен через ротации).
- Резолв `@name` → `identity_id` (eclipse-resistant quorum).
- Forward-secret синхронное E2E (X3DH-prekeys + ML-KEM fan-out).
- Доставку сообщений на **онлайн** инстансы нескольких устройств
  + fan-out state-blob'а между собственными инстансами (см.
  [`integration_tests::scenario_app_state_sync_*`](../../crates/veil-identity/src/integration_tests.rs)).
- Safety-номер fingerprint для out-of-band-верификации.
- Бэкап → восстановление через бумажную BIP-39 фразу (см.
  [`integration_tests::scenario_chat_backup_restore_roundtrip`](../../crates/veil-identity/src/integration_tests.rs)).

**НЕ даёт**:

- **Async / offline-доставку** — у veil нет in-network mailbox
  подсистемы. Если вашему мессенджеру нужен durable async, стройте
  это отдельным крейтом (`veil-mailbox`, ещё не реализован; или
  используйте `DHT.store` с TTL, self-sync между несколькими
  узлами или внешний relay).
- **Revocation + восстановление после компрометации** — у veil
  нет in-band revocation gossip, нет `RevocationCache`, нет
  `master_freshness_sig`. Сегодняшний recovery flow: короткоживущий
  `IdentityKey.valid_until` (≤7 дней) + переиздание из master.
  Долгосрочный revocation-крейт — open backlog.
- Схемы содержимого сообщений — выбирайте свою (protobuf, JSON,
  что угодно).
- Групповой чат — рекомендуется MLS (RFC 9420); любая библиотека,
  говорящая на MLS, подключается на прикладном уровне.
- Presence / typing indicators / read receipts — стройте поверх,
  используя app_state fan-out + прямые сессии.
- Voice/video — real-time stream-канал veil переносит медиа;
  свой SDP-обмен делайте сверху.
- Доставку push-нотификаций в мобильные ОС — veil эмитит
  `WakeHint`; ваше мобильное приложение само разруливает
  APN/FCM round-trip.

---

## 2. Минимально жизнеспособный мессенджер на примитивах veil

```
                                   ┌──────────────────────────┐
   1. «alice» вводит «hi bob»      │ app text input           │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   2. Резолв @bob                  │ NameResolver::resolve    │
                                   │   ↳ quorum DHT fetch     │
                                   │   ↳ verify cert chain    │
                                   │   → ValidatedIdentity    │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   3. Получить ML-KEM-серты Bob'а  │ fetch InstanceRegistry   │
                                   │ fetch each MlKemKeyCert  │
                                   │ verify_mlkem_cert × N    │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   4. Сначала пытаемся X3DH-prekey │ fetch PrekeyBundle для   │
      (forward secrecy)            │ each recipient instance  │
                                   │ pick_for_send            │
                                   │ x3dh::sender_encapsulate │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   5. ML-KEM fan-out encrypt       │ fanout_encrypt(payload,  │
                                   │   verified_certs,        │
                                   │   sender_id, bob_id)     │
                                   │ → Vec<FanoutEnvelope>    │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   6. Обернуть в DELIVERY_FORWARD  │ Recipient::All(bob_id)   │
                                   │ → veil dispatcher        │
                                   └───────────┬──────────────┘
                                               │
          ════════════════════════════════════╪═══════════════
                                               ▼     (wire)

                                   ┌──────────────────────────┐
   7. Только online-доставка       │ dispatcher.deliver():    │
                                   │  for each bob.instance{  │
                                   │   if online → push;      │
                                   │   else → SendFailed.     │
                                   │  }                       │
                                   └───────────┬──────────────┘
                                               │
                          ┌────────────────────┴──────────────┐
                          │                                   │
                  ┌───────▼─────┐                      ┌──────▼───────┐
                  │ bob phone   │ (online)             │ bob laptop   │ (offline)
                  │ принимает   │                      │ — отправитель│
                  │ envelope[1] │                      │ получает     │
                  └───────┬─────┘                      │ SendFailed   │
                          │                            │ для inst[2]  │
                          │                            └──────────────┘
                  ┌───────▼──────────────────────────────────────┐
                  │ phone выбирает свой FanoutEnvelope           │
                  │ recipient_decapsulate через локальный ML-KEM │
                  │ AEAD-расшифровка payload                     │
                  │ форвардит в приложение («входящее от @alice»)│
                  └──────────────────────────────────────────────┘
```

Все veil-side шаги уже реализованы (см.
[`integration_tests::scenario_multi_device_fanout_messenger`](../../crates/veil-identity/src/integration_tests.rs)).
Ваше приложение сидит вверху и внизу этой диаграммы.

> **Async / offline-доставка вне scope сетевого уровня.**
> У veil нет in-network mailbox. Если вашему мессенджеру нужно
> store-and-forward для офлайновых получателей, стройте это сверху:
> либо отдельный крейт `veil-mailbox` (TBD), либо существующие
> примитивы (`DHT.store` с TTL на известном shard'е, либо выберите
> онлайн relay-peer на каждого получателя и реплицируйте).

---

## 3. Cheat-sheet библиотек

Быстрая указатель-таблица по текущим примитивам. Раскладка крейтов:
identity-примитивы живут в
[`veil-identity`](../../crates/veil-identity/), крипто —
в [`veil-crypto`](../../crates/veil-crypto/), wire-типы —
в [`veil-proto`](../../crates/veil-proto/).

| Концерн | Модуль | Ключевые точки входа |
|---------|--------|----------------------|
| Резолв адреса (`@bob` → identity) | [`veil-identity/resolver.rs`] | `NameResolver::resolve`, `VerifyConfig::resolver_quorum` |
| Верификация identity-документа | [`veil-identity/verify.rs`] | `verify_identity_document` |
| Бумажный бэкап master-seed (BIP-39) | [`veil-identity/master_seed.rs`] | `encode_master_seed_to_phrase`, `decode_master_seed_from_phrase` |
| Шифрованный файл master-seed (Argon2id + ChaCha20) | [`veil-identity/master_file.rs`] | `save_master_seed_encrypted_with`, `load_master_seed_encrypted` |
| Per-device состояние инстанса | [`veil-identity/instance.rs`] | `LocalInstance::load_or_init` |
| ML-KEM cert + fan-out (multi-device) | [`veil-identity/mlkem_fanout.rs`] | `verify_mlkem_cert`, `fanout_encrypt`, `fanout_decrypt_one` |
| X3DH prekeys (forward secrecy) | [`veil-crypto/x3dh.rs`] | `generate_prekey`, `sender_encapsulate`, `recipient_decapsulate` |
| Safety-номер fingerprint | [`veil-crypto/identity_fingerprint.rs`] | `identity_fingerprint` |
| Freshness lifecycle (когда переопубликовать документ) | [`veil-identity/freshness.rs`] | `severity`, `needs_refresh` |
| Wire-типы identity | [`veil-proto/identity_document.rs`] | `IdentityDocument`, `IdentityKey` |
| Wire-формат ML-KEM cert | [`veil-proto/mlkem_cert.rs`] | `MlKemKeyCert`, `MLKEM_CERT_SIG_CONTEXT` |
| Wire-формат prekey-bundle | [`veil-proto/prekey_bundle.rs`] | `PrekeyBundle`, `ALGO_ML_KEM_768` |
| Типы адресации | [`veil-proto/recipient.rs`] | `Recipient`, `InstanceTag` |
| Wake-up hint (мобильный push) | [`veil-proto/wake_hint.rs`] | `WakeHint` |

[`veil-identity/resolver.rs`]: ../crates/veil-identity/src/resolver.rs
[`veil-identity/verify.rs`]: ../crates/veil-identity/src/verify.rs
[`veil-identity/master_seed.rs`]: ../crates/veil-identity/src/master_seed.rs
[`veil-identity/master_file.rs`]: ../crates/veil-identity/src/master_file.rs
[`veil-identity/instance.rs`]: ../crates/veil-identity/src/instance.rs
[`veil-identity/mlkem_fanout.rs`]: ../crates/veil-identity/src/mlkem_fanout.rs
[`veil-identity/freshness.rs`]: ../crates/veil-identity/src/freshness.rs
[`veil-crypto/x3dh.rs`]: ../crates/veil-crypto/src/x3dh.rs
[`veil-crypto/identity_fingerprint.rs`]: ../crates/veil-crypto/src/identity_fingerprint.rs
[`veil-proto/identity_document.rs`]: ../crates/veil-proto/src/identity_document.rs
[`veil-proto/mlkem_cert.rs`]: ../crates/veil-proto/src/mlkem_cert.rs
[`veil-proto/prekey_bundle.rs`]: ../crates/veil-proto/src/prekey_bundle.rs
[`veil-proto/recipient.rs`]: ../crates/veil-proto/src/recipient.rs
[`veil-proto/wake_hint.rs`]: ../crates/veil-proto/src/wake_hint.rs

> **Убрано архитектурным решением**:
> `revocation_cache.rs`, `propagate.rs` (revocation gossip),
> `watcher.rs` (anomaly), `tier_b.rs`, `mailbox/*` — ни одного из
> них нет в текущем сетевом слое. Async-delivery и revocation-крейты
> могут вернуться как **отдельные** крейты, наслоенные поверх
> сетевого слоя (пока не реализованы). Разделы 4-7 ниже могут
> по-прежнему ссылаться на эти API; авторитетен cheat-sheet выше.

---

## 4. Строим happy path

### 4.1. Формат сообщения прикладного уровня

Ваши сообщения для veil непрозрачны — подойдёт любая
сериализация. Хорошая стартовая точка:

```rust
struct AppMessage {
    msg_id: [u8; 16],          // random
    ts_unix_millis: u64,
    sender_name: String,       // "@alice" for display only
    kind: AppMessageKind,
    body: Vec<u8>,             // protobuf / JSON / whatever
}

enum AppMessageKind {
    Text,
    Typing,
    Delivered { ref_msg_id: [u8; 16] },
    Read { ref_msg_id: [u8; 16] },
}
```

Сериализуйте в байты — именно их видит `fanout_encrypt`.

### 4.2. Резолв получателя

```rust
use veilcore::node::identity::resolver::{NameResolver, VerifyConfig};
use veilcore::node::identity::revocation_cache::RevocationCache;

let cfg = VerifyConfig {
    resolver_quorum: 2,            // require 2 matching replicas
    resolver_max_replicas: 5,
    ..Default::default()
};
let resolver = NameResolver::with_config(my_backend.clone(), cfg);
let cache = RevocationCache::open(config_dir.join("revocations.bin"))?;

let validated = resolver.resolve("alice", &cache, now_unix_secs()).await?;
let recipient_identity_id = validated.id;
```

Резолвер кеширует `alice → identity_id` до 5 минут после первого
успеха, так что повторные отправки дёшевы.

### 4.3. Получаем инстансы получателя + ML-KEM серты

```rust
use veilcore::node::identity::mlkem_fanout::{
    verify_mlkem_cert, fanout_encrypt,
};
use veilcore::proto::mlkem_cert::MlKemKeyCert;
use veilcore::proto::instance_registry::InstanceRegistry;

let registry_bytes = backend
    .fetch(InstanceRegistry::dht_key(&recipient_identity_id))
    .await?
    .ok_or("no registry for recipient")?;
let registry = InstanceRegistry::decode(&registry_bytes)?;

// (Verify registry signature + identity binding — см. identity-model.md §8.)

let mut certs = Vec::new();
for entry in &registry.instances {
    let bytes = backend
        .fetch(MlKemKeyCert::dht_key_for(&recipient_identity_id, &entry.instance_id))
        .await?
        .ok_or("missing cert")?;
    let cert = MlKemKeyCert::decode(&bytes)?;
    certs.push(verify_mlkem_cert(&cert, &recipient_doc, now_unix_secs())?);
}
```

### 4.4. Шифрование + отправка

```rust
let envelopes = fanout_encrypt(
    &serialised_message,
    &certs,
    &my_identity_id,
    &recipient_identity_id,
)?;

for env in envelopes {
    dispatcher.enqueue_forward(Recipient::specific(recipient_identity_id, env.recipient_instance_id), env)?;
}
```

Это исходящий путь.

### 4.5. Приём + расшифровка

На стороне получателя, каждый раз когда mailbox отдаёт входящий
`FanoutEnvelope`:

```rust
use veilcore::node::identity::mlkem_fanout::fanout_decrypt_one;

let plaintext = fanout_decrypt_one(
    &[envelope],
    &my_instance_id,
    &my_identity_id,
    &sender_identity_id,
    &my_mlkem_dk_seed,
    my_current_cert_version,
)?;

let msg: AppMessage = deserialise(&plaintext)?;
app_display_inbound(msg);
```

### 4.6. Для по-настоящему async-доставки: сначала X3DH prekeys, fallback на ML-KEM cert

Forward secrecy важна, когда получатель оффлайн. Сообщение лежит
в DHT/mailbox достаточно долго, чтобы поздняя компрометация
долгоживущего ML-KEM ключа смогла его расшифровать. X3DH prekeys
решают эту проблему: одноразовый ключ, который потребляется
и удаляется.

```rust
use veilcore::proto::prekey_bundle::PrekeyBundle;
use veilcore::crypto::x3dh::sender_encapsulate;

let bundle_bytes = backend
    .fetch(PrekeyBundle::dht_key(&recipient_identity_id, &recipient_instance_id))
    .await?;
let bundle = PrekeyBundle::decode(&bundle_bytes?)?;
// (Verify bundle.sig under recipient's identity_sk.)

match bundle.pick_for_send(&my_consumed_prekey_ids, now_unix_secs()) {
    PickedPrekey::OneTime(p) => {
        let enc = sender_encapsulate(
            bundle.algo, &p.encapsulation_key,
            &my_identity_id, &recipient_identity_id, &recipient_instance_id,
            p.prekey_id,
        )?;
        // Помечаем prekey потреблённым локально, чтобы избежать reuse.
        my_consumed_prekey_ids.insert(p.prekey_id);
        send(enc, p.prekey_id, /* one_time = */ true);
    }
    PickedPrekey::Fallback(fb) => {
        // Пул исчерпан — fallback с ослабленной FS, но всё ещё защищено.
        let enc = sender_encapsulate(/* ... */)?;
        send(enc, fb.prekey_id, /* one_time = */ false);
    }
    PickedPrekey::None => {
        // Все prekey'и просрочены; fallback на опубликованный
        // инстансом MlKemKeyCert (долгоживущий). Forward secrecy
        // снижена, но сообщение проходит.
    }
}
```

### 4.7. Синхронизация списка контактов между устройствами

```rust
use veilcore::proto::app_state::{encrypt_app_state, decrypt_app_state, AppState};

// Write:
let mut state = encrypt_app_state(
    my_identity_id,
    "messenger".into(),
    b"contacts".to_vec(),
    &serialised_contacts,
    &my_app_state_secret,
    current_version + 1,
    now_unix_secs(),
    my_signing_key_idx,
)?;
state.sig = sign(state.canonical_signing_bytes())?;
backend.put(AppState::dht_key(&my_identity_id, "messenger", b"contacts"), state.encode()).await?;

// Read (на любом из ваших устройств):
let bytes = backend.fetch(AppState::dht_key(&my_identity_id, "messenger", b"contacts")).await?;
let state = AppState::decode(&bytes?)?;
// (Verify state.sig under any active identity_sk of my identity.)
let contacts = decrypt_app_state(&state, &my_app_state_secret)?;
```

### 4.8. Поверхностный показ смены safety-номера

Храните последний наблюдавшийся safety-номер на каждый контакт.
Когда вы резолвите контакт и итоговый fingerprint `(my_id, their_id)`
отличается от сохранённого, показывайте алерт:

```
Safety-номер Alice изменился.
Текущий:  12345 67890 13579 24680 11223 33445
                55667 78899 00112 23344 55667 78899
Свяжитесь с Alice вне veil, чтобы verify'нуть, прежде чем
отправлять что-либо чувствительное.
```

Функция `identity_fingerprint` даёт каноническую форму
(60 цифр, 12 групп по 5):

```rust
use veilcore::crypto::identity_fingerprint::identity_fingerprint;
let number = identity_fingerprint(&my_id, &their_id);
```

### 4.9. UX сопряжения устройства

Слушайте фреймы `DeviceLinkedEvent` в потоке входящих сообщений.
Покажите пользователю:

```
К вашей identity сопряжено новое устройство:
  Имя: Pixel 8a
  Сопряжено с: MacBook Pro 2025
  Время: 2026-04-20 15:32 UTC

Это инициировали вы?  [ Да, я ]  [ НЕТ — помогите! ]
```

Если он нажмёт «НЕТ», немедленно:

1. Отзовите новый `identity_key` с master-устройства.
2. Запустите anomaly-watcher.
3. Рассмотрите полную ротацию (сценарий компрометации).

---

## 5. Групповой чат — MLS

Veil явно НЕ реализует криптографию группового чата. Правильный
примитив — MLS (RFC 9420). Типичная интеграция:

- Каждый участник запускает MLS-библиотеку (`openmls` — production-quality
  на Rust).
- MLS welcome-сообщения, commit'ы и application-сообщения переносятся
  внутри `DELIVERY_FORWARD` veil как непрозрачные байты.
- Veil отвечает за транспорт + identity; MLS — за состояние группы.

Стык чистый: MLS-сессии используют `identity_id` veil как
долгосрочный identity-ключ каждого участника; safety-номер
fingerprint veil верифицирует identity один раз out-of-band,
а дальше MLS берёт на себя криптографию группы.

---

## 6. Первый запуск пользователя

UX, который все делают неправильно:

```
Добро пожаловать в [ваш мессенджер].

Чтобы начать, выберите имя identity:  [__________]

[ ] У меня уже есть identity (восстановление из бэкапа)
```

Что пользователю реально нужно по порядку:

1. **Выбрать имя** (ваш UI должен резолвить в реальном времени,
   чтобы показывать, занято ли).
2. **Увидеть BIP-39 фразу + подтверждение.** Дайте пользователю
   физически её записать. Покажите режим veil для показа
   фразы (приглушённый экран, без scrollback) и заставьте
   перепечатать 3 случайные позиции, прежде чем продолжить.
3. **Опционально задать пароль master-файла** для локального
   шифрованного бэкапа. Пропуск по умолчанию — бумага и есть
   реальный durable-бэкап.
4. **Сгенерировать QR-код для шеринга контакта.** Поощряйте
   делать скриншот или сохранять в облако — он не содержит
   секретов, только публичный `identity_id` + предпочитаемое имя.
5. **Предложить добавить контакты** или **сопрячь другое
   устройство**.

Round-trip pair-invite + pair-accept со сверкой OOB-кода должен
укладываться в 90 секунд на типичном пользовательском сетапе.

---

## 7. Стратегия тестирования для интеграций приложений

`veilcore` экспонирует свои бэкенды как trait'ы — используйте
in-memory подделки в ваших интеграционных тестах:

- `NameLookup` + `IdentityLookup` (см. тесты `resolver.rs`).
- Сконструируйте свой `MemBackend` и завязывайтесь на него так же,
  как это делают существующие тесты veil.
- Генерируйте тестовые identity с `master_seed = [0x42u8; 32]`,
  чтобы тесты были детерминированными.

Reference-паттерны живут в каждом модуле `tests` в `veilcore` —
они намеренно многословны, чтобы заодно служить документацией.

---

## 8. Чеклист перед релизом вашей v1

☐ BIP-39 фраза отображается при создании, пользователь
перепечатывает подтверждение, экран приглушён.

☐ Поддержка шифрованного master-файла, если вы не paper-only.

☐ Контакты синхронизированы через `AppState` (не через ad-hoc
DHT-запись).

☐ Fan-out-шифрование для multi-device получателей.

☐ Поддерживается пул X3DH prekey'ев — пополнять, когда падает
ниже `MIN_PREKEY_POOL_REMAINING = 3`.

☐ Persistent revocation cache в
`~/.config/veil/revocations.bin`.

☐ Quorum-резолвер включён (`resolver_quorum = 2`).

☐ Показ safety-номера в профилях контактов.

☐ Алерты `DeviceLinkedEvent`.

☐ Anomaly watcher запускается при каждом старте (показывает
warning'и, если есть).

☐ Курсоры mailbox трекаются per-instance (общий mailbox, не
per-device состояние).

☐ Запланирован refresh freshness (`veil-cli identity
refresh-freshness` или эквивалентная автоматизация) ≥ каждые
25 дней.

☐ User-facing docs ссылаются на
[`opsec-user-guide.md`](opsec-user-guide.md) и
[`recovery.md`](recovery.md).

---

## 9. Куда задавать вопросы

- Детали протокола: [`identity-model.md`](identity-model.md)
  §10 (threat model) и §11 (algorithm agility).
- Баги интеграции: issue tracker veil, label
  `integration-help`.
- Криптографический review: RFCs veil в `docs/rfcs/`.
