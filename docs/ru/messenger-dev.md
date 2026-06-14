# Мессенджер: руководство разработчика

Как построить мессенджер в стиле Signal поверх veil. Тот же рецепт
подойдёт любому приложению, которому нужна суверенная личность
(identity — учётная запись, принадлежащая пользователю, а не серверу)
плюс асинхронная доставка (сообщения, доходящие до получателя, который
сейчас офлайн).

Этот документ показывает, где искать нужные API. За точными сигнатурами
идите в связанные исходные файлы. За поведением, которое видит
пользователь, — в сопутствующие документы.

- [`identity-model.md`](identity-model.md) — спецификация протокола.
- [`multi-device.md`](multi-device.md) — разделение двух режимов работы
  (балансировщик нагрузки и мессенджер).
- [`recovery.md`](recovery.md) — восстановление с точки зрения
  пользователя.
- [`opsec-user-guide.md`](opsec-user-guide.md) — этот документ раздавайте
  своим пользователям.

---

## 1. Что veil даёт, а что не даёт

**Даёт**:

- Суверенную личность. Идентификатор `identity_id` остаётся стабильным
  даже когда лежащие в основе ключи проходят ротацию.
- Разрешение имени: `@name` → `identity_id`. Оно опирается на кворум
  (несколько независимых реплик должны согласиться), поэтому один
  вредоносный узел не подсунет вам поддельный ответ.
- Сквозное (end-to-end, E2E) шифрование с прямой секретностью для
  сообщений, отправленных, пока получатель онлайн. Собрано из
  предключей X3DH и веерной (fan-out) рассылки ML-KEM — оба понятия
  разобраны в разделе 2. Прямая секретность (forward secrecy) означает,
  что кража сегодняшних ключей не расшифрует вчерашние сообщения.
- Доставку сообщений на **онлайн**-экземпляры получателя на всех его
  устройствах плюс веерную рассылку блоба состояния между вашими
  *собственными* экземплярами (см.
  [`integration_tests::scenario_app_state_sync_*`](../../crates/veil-identity/src/integration_tests.rs)).
  Экземпляр (instance) — это работающая копия личности на одном
  устройстве.
- Отпечатки безопасности (safety-number fingerprint): короткие
  числовые коды, которые два человека зачитывают друг другу по
  отдельному каналу (по телефону, при встрече), чтобы убедиться, что
  никто не выдаёт себя за другую сторону.
- Резервное копирование и восстановление через бумажную фразу BIP-39 —
  список слов, который вы записываете на бумаге (см.
  [`integration_tests::scenario_chat_backup_restore_roundtrip`](../../crates/veil-identity/src/integration_tests.rs)).

**НЕ даёт**:

- **Асинхронная / офлайн-доставка включается по желанию, по умолчанию
  выключена.** У veil есть почтовый ящик (`veil-mailbox`) для надёжной
  асинхронной доставки — зашифрованные блобы ждут офлайнового получателя
  и переживают перезапуск, — но в демоне `[mailbox] enabled` по умолчанию
  выключен. Когда вы его включите, депозиты ограничены поучастниковыми и
  глобальными квотами и лимитом частоты; в продакшене ставьте
  `mailbox.require_capability_token = true`, чтобы депонировать могли
  только отправители с токеном (по умолчанию режим разрешительный ради
  обратной совместимости). Если запускать почтовый ящик вы не хотите,
  старые примитивы по-прежнему работают — `DHT.store` с TTL (запись,
  которую сеть удаляет по истечении времени жизни), самосинхронизация
  между вашими узлами или внешний ретранслятор.
- **Отзыв ключей и восстановление после компрометации.** У veil нет
  встроенного в протокол способа разослать «этот ключ отозван» — нет
  `RevocationCache`, нет `master_freshness_sig`. Сегодняшний путь
  восстановления проще: каждый `IdentityKey` короткоживущий
  (`valid_until` ≤ 7 дней), и вы переиздаёте свежий из мастер-ключа.
  Полноценный крейт долгосрочного отзыва пока в списке задач.
- Схемы содержимого сообщений. Выбирайте свою — protobuf, JSON, что
  угодно.
- Групповой чат. Используйте MLS (RFC 9420). Любая библиотека,
  говорящая на MLS, встаёт на место на прикладном уровне.
- Присутствие, индикаторы набора, отметки о прочтении. Стройте их
  поверх, используя веерную рассылку app_state и прямые сессии.
- Голос и видео. Канал потоковой передачи veil в реальном времени
  несёт медиа; обмен SDP (рукопожатие установки звонка в WebRTC) вы
  накладываете сверху.
- Доставку push-уведомлений в мобильные ОС. Veil испускает `WakeHint`;
  ваше мобильное приложение само ведёт обмен с push-службой Apple или
  Google (APN / FCM).

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

Каждый шаг на стороне veil здесь уже реализован (см.
[`integration_tests::scenario_multi_device_fanout_messenger`](../../crates/veil-identity/src/integration_tests.rs)).
Ваше приложение даёт верх и низ этой диаграммы; середину делает veil.

> **Асинхронная / офлайн-доставка уже реализована через `veil-mailbox`.**
> Когда получатель офлайн, узел отправителя депонирует зашифрованный блоб
> в почтовый ящик store-and-forward на одном из реплика-ретрансляторов
> получателя; получатель забирает и подтверждает ожидающие блобы, как
> только снова выходит в сеть (или просыпается по push-уведомлению), и
> ретранслятор после этого их удаляет. Хранилище — это надёжный KV на
> redb (переживает перезапуск ретранслятора) с квотами на получателя и на
> ретранслятор, TTL на каждый блоб и лимитом частоты депозитов. Оно
> **включается по желанию**: в демоне `[mailbox] enabled` по умолчанию
> выключен, так что включите его (и поставьте
> `mailbox.require_capability_token = true` в продакшене), если вашему
> мессенджеру нужна офлайн-доставка. Если запускать почтовый ящик вы не
> хотите, старые примитивы по-прежнему работают — `DHT.store` с TTL на
> известном шарде (фиксированном срезе адресного пространства), либо
> выберите один онлайн-ретранслятор на каждого получателя и реплицируйте
> на него.

---

## 3. Шпаргалка по библиотекам

Быстрая таблица-указатель по текущим примитивам. Крейты делятся так:
примитивы личности живут в
[`veil-identity`](../../crates/veil-identity/), криптография —
в [`veil-crypto`](../../crates/veil-crypto/), а wire-типы (структуры,
которые реально идут по сети) —
в [`veil-proto`](../../crates/veil-proto/).

| Задача | Модуль | Ключевые точки входа |
|---------|--------|----------------------|
| Разрешение адреса (`@bob` → личность) | [`veil-identity/resolver.rs`] | `NameResolver::resolve`, `VerifyConfig::resolver_quorum` |
| Проверка документа личности | [`veil-identity/verify.rs`] | `verify_identity_document` |
| Бумажная копия master-seed (BIP-39) | [`veil-identity/master_seed.rs`] | `encode_master_seed_to_phrase`, `decode_master_seed_from_phrase` |
| Шифрованный файл master-seed (Argon2id + ChaCha20) | [`veil-identity/master_file.rs`] | `save_master_seed_encrypted_with`, `load_master_seed_encrypted` |
| Состояние экземпляра на каждом устройстве | [`veil-identity/instance.rs`] | `LocalInstance::load_or_init` |
| Сертификат ML-KEM + веерная рассылка (несколько устройств) | [`veil-identity/mlkem_fanout.rs`] | `verify_mlkem_cert`, `fanout_encrypt`, `fanout_decrypt_one` |
| Предключи X3DH (прямая секретность) | [`veil-crypto/x3dh.rs`] | `generate_prekey`, `sender_encapsulate`, `recipient_decapsulate` |
| Отпечаток безопасности (safety number) | [`veil-crypto/identity_fingerprint.rs`] | `identity_fingerprint` |
| Жизненный цикл свежести (когда переопубликовать документ) | [`veil-identity/freshness.rs`] | `severity`, `needs_refresh` |
| Wire-типы личности | [`veil-proto/identity_document.rs`] | `IdentityDocument`, `IdentityKey` |
| Wire-формат сертификата ML-KEM | [`veil-proto/mlkem_cert.rs`] | `MlKemKeyCert`, `MLKEM_CERT_SIG_CONTEXT` |
| Wire-формат набора предключей | [`veil-proto/prekey_bundle.rs`] | `PrekeyBundle`, `ALGO_ML_KEM_768` |
| Типы адресации | [`veil-proto/recipient.rs`] | `Recipient`, `InstanceTag` |
| Подсказка для пробуждения (мобильный push) | [`veil-proto/wake_hint.rs`] | `WakeHint` |

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
> `revocation_cache.rs`, `propagate.rs` (рассылка отзывов),
> `watcher.rs` (обнаружение аномалий), `tier_b.rs`. Ни одного из них
> больше нет — нет ни встроенного в протокол отзыва, ни наблюдателя
> аномалий. Свежесть личности — это просто короткое окно
> `valid_until_unix` (см. `freshness.rs`); скомпрометированный подключ
> устаревает, а не отзывается. Асинхронная / офлайн-доставка, напротив,
> **реализована** — отдельным, включаемым по желанию крейтом
> `veil-mailbox` (см. §1 и §2), а не частью ядра сетевого слоя.

---

## 4. Строим основной путь

### 4.1. Формат сообщения прикладного уровня

Veil никогда не заглядывает внутрь ваших сообщений, поэтому подойдёт
любая сериализация. Вот разумная отправная точка:

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

Сериализуйте в байты. Именно эти байты и видит `fanout_encrypt`.

### 4.2. Разрешение получателя

Разрешить (resolve) — значит превратить человекочитаемое `@name` в тот
`identity_id`, на который вы на самом деле отправляете.

```rust
use veilcore::node::identity::resolver::{NameResolver, VerifyConfig};

let cfg = VerifyConfig {
    resolver_quorum: 2,            // require 2 matching replicas
    resolver_max_replicas: 5,
    ..Default::default()
};
let resolver = NameResolver::with_config(my_backend.clone(), cfg);

let validated = resolver.resolve("alice", now_unix_secs()).await?;
let recipient_identity_id = validated.id;
```

Кеша отзывов, в который надо заглядывать, нет: свежесть личности — это
короткое окно `valid_until_unix` в подписанном документе, которое
резолвер проверяет относительно `now_unix_secs()`. Подключ, которому
больше не следует доверять, просто устаревает по истечении своего окна,
а не отзывается. После первого удачного запроса резолвер кеширует
`alice → identity_id` на срок до 5 минут. Повторные отправки в это
окно дёшевы — второго запроса к кворуму не будет.

### 4.3. Получаем экземпляры получателя и сертификаты ML-KEM

Теперь вы знаете, *кто* такой Bob. Дальше нужно понять, *куда*
отправлять: по одному сертификату ML-KEM на каждое его онлайн-устройство.
Реестр перечисляет его устройства; каждое устройство публикует
собственный сертификат.

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

### 4.4. Шифрование и отправка

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

Это и есть весь исходящий путь.

### 4.5. Приём и расшифровка

На стороне получателя выполняйте это каждый раз, когда почтовый ящик
отдаёт вам входящий `FanoutEnvelope` (одну запечатанную копию
сообщения, адресованную одному устройству):

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

### 4.6. Для по-настоящему асинхронной доставки: сначала предключи X3DH, сертификат ML-KEM как запасной путь

Прямая секретность важнее всего, когда получатель офлайн. Сообщение
тогда какое-то время лежит в DHT или почтовом ящике. Если кто-то позже
украдёт долгоживущий ключ ML-KEM, он сможет расшифровать это ждущее
сообщение. Предключи X3DH закрывают эту брешь. Предключ (prekey) —
одноразовый ключ, который получатель публикует заранее; отправитель
использует его один раз, после чего ключ потребляется и удаляется,
так что повторно ничего расшифровать им нельзя.

У логики выбора три исхода в порядке предпочтения: свежий одноразовый
предключ; переиспользуемый запасной предключ, когда пул пуст; а если
нет и таких — долгоживущий сертификат устройства.

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

Храните список контактов как запись `AppState`: один шифрованный блоб,
подписанный вашей личностью, который каждое из ваших устройств может
прочитать и перезаписать. Повышайте версию при каждой записи, чтобы
устройства понимали, какая копия новее.

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

### 4.8. Показывайте смену отпечатка безопасности

Храните последний отпечаток безопасности (safety number), который вы
видели для каждого контакта. Каждый раз, разрешая этот контакт,
пересчитывайте отпечаток `(my_id, their_id)`. Если он отличается от
сохранённого, ключи контакта сменились — это нормально после
переустановки, но так же выглядит и атака с подменой личности. В любом
случае предупредите пользователя:

```
Safety-номер Alice изменился.
Текущий:  12345 67890 13579 24680 11223 33445
                55667 78899 00112 23344 55667 78899
Свяжитесь с Alice вне veil, чтобы verify'нуть, прежде чем
отправлять что-либо чувствительное.
```

Функция `identity_fingerprint` возвращает этот номер в канонической
форме — 60 цифр, показанные как 12 групп по 5:

```rust
use veilcore::crypto::identity_fingerprint::identity_fingerprint;
let number = identity_fingerprint(&my_id, &their_id);
```

### 4.9. UX привязки устройства

Следите за кадрами `DeviceLinkedEvent` в потоке входящих сообщений.
Такой кадр приходит каждый раз, когда к личности привязывается новое
устройство. Покажите пользователю, что произошло:

```
К вашей identity сопряжено новое устройство:
  Имя: Pixel 8a
  Сопряжено с: MacBook Pro 2025
  Время: 2026-04-20 15:32 UTC

Это инициировали вы?  [ Да, я ]  [ НЕТ — помогите! ]
```

Если он нажмёт «НЕТ», считайте это возможной компрометацией и
действуйте сразу:

1. Прокрутите подписной подключ этого устройства с мастер-устройства
   (`veil-cli identity rotate`) и переопубликуйте документ личности,
   чтобы нежелательный подключ устарел по истечении своего окна
   `valid_until_unix`. Встроенного в протокол отзыва нет; ущерб
   ограничивает именно короткое окно.
2. Проверьте список привязанных устройств и отвяжите все незнакомые.
3. Если под угрозой сам мастер-сид, исходите из худшего: создайте новую
   личность из нового сида и перенесите на неё контакты.

---

## 5. Групповой чат — MLS

Veil намеренно НЕ реализует криптографию группового чата. Правильный
инструмент для этого — MLS (Messaging Layer Security, RFC 9420).
Типичная интеграция выглядит так:

- Каждый участник запускает MLS-библиотеку (`openmls` — зрелая
  реализация на Rust, готовая к продакшену).
- MLS-сообщения любого рода — приглашения (welcome), коммиты и
  прикладные сообщения — едут внутри `DELIVERY_FORWARD` veil как
  непрозрачные байты. Veil их не разбирает.
- Veil отвечает за транспорт и личность; MLS — за общее состояние
  группы.

Передача ответственности чистая. Каждая MLS-сессия использует
`identity_id` veil как долгосрочный ключ личности участника. Личность
вы проверяете один раз, по отдельному каналу, через отпечаток
безопасности veil — а дальше криптографию группы берёт на себя MLS.

---

## 6. Первый запуск пользователя

Вот экран первого запуска, который почти все делают неправильно:

```
Добро пожаловать в [ваш мессенджер].

Чтобы начать, выберите имя identity:  [__________]

[ ] У меня уже есть identity (восстановление из бэкапа)
```

Что пользователю реально нужно, по порядку:

1. **Выбрать имя.** Разрешайте его в реальном времени, пока он
   набирает, чтобы он видел, не занято ли оно.
2. **Увидеть фразу BIP-39, затем подтвердить её.** Дайте пользователю
   записать её на бумаге. Покажите её в режиме показа фразы veil —
   приглушённый экран, без прокрутки назад — и заставьте перепечатать
   3 случайные позиции, прежде чем двигаться дальше.
3. **При желании задать пароль мастер-файла** для локальной шифрованной
   копии. По умолчанию пропустите. Бумага — это копия, которая
   действительно надолго; шифрованный файл лишь для удобства.
4. **Сгенерировать QR-код, чтобы поделиться контактом.** Поощряйте
   сделать скриншот или сохранить в облако — секретов в нём нет, только
   публичный `identity_id` и предпочитаемое имя.
5. **Предложить добавить контакты** или **привязать другое
   устройство**.

Полный обмен «приглашение в пару + принятие пары», включая сверку кода
по отдельному каналу, должен укладываться в 90 секунд на типичном
пользовательском оборудовании.

---

## 7. Стратегия тестирования для интеграций приложений

`veilcore` выставляет свои бэкенды как трейты, поэтому ваши
интеграционные тесты могут подставлять подделки в памяти вместо
обращения к настоящей сети:

- Подделайте `NameLookup` и `IdentityLookup` (как — см. тесты в
  `resolver.rs`).
- Соберите собственный `MemBackend` и подключите его ровно так же, как
  это делают собственные тесты veil.
- Генерируйте тестовые личности из фиксированного зерна,
  `master_seed = [0x42u8; 32]`, чтобы каждый прогон был
  детерминированным.

Образцовые примеры есть в каждом модуле `tests` по всему `veilcore`.
Они намеренно многословны, чтобы заодно служить разобранными примерами.

---

## 8. Чеклист перед релизом вашей v1

☐ Фраза BIP-39 показывается при создании, на приглушённом экране, с
перепечаткой для подтверждения.

☐ Поддержка шифрованного мастер-файла, если вы не ограничиваетесь
только бумагой.

☐ Контакты синхронизированы через `AppState`, а не через случайную
DHT-запись.

☐ Веерное шифрование для получателей с несколькими устройствами.

☐ Пул предключей X3DH держится пополненным — доливайте его всякий раз,
когда он падает ниже `MIN_PREKEY_POOL_REMAINING = 3`.

☐ Резолвер с кворумом включён (`resolver_quorum = 2`).

☐ Отпечаток безопасности показан в профиле каждого контакта.

☐ Оповещения `DeviceLinkedEvent` подключены.

☐ Курсоры почтового ящика отслеживаются на каждый экземпляр — ящик
общий, поэтому это не состояние отдельного устройства.

☐ Документ личности переопубликован до истечения `valid_until_unix` —
запланируйте это внутри окна свежести (`freshness::needs_refresh`; по
спецификации переопубликация происходит за 5 дней до истечения 30-
дневного окна), своей автоматизацией. Для рутинной гигиены подключей
используйте `veil-cli identity rotate`; отзыва нет, поэтому короткое
окно и есть механизм свежести.

☐ Документы для пользователей ссылаются на
[`opsec-user-guide.md`](opsec-user-guide.md) и
[`recovery.md`](recovery.md).

---

## 9. Куда задавать вопросы

- Детали протокола: [`identity-model.md`](identity-model.md),
  §10 (модель угроз) и §11 (гибкость выбора алгоритмов).
- Баги интеграции: трекер задач veil, метка
  `integration-help`.
- Криптографический разбор: RFC veil в `docs/rfcs/`.
