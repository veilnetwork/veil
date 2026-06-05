# Multi-device гайд

Как veil обрабатывает несколько устройств под одной identity —
будь то цель балансировки сервис-флота или синхронизация сообщений
между телефоном пользователя, ноутбуком и десктопом.

Про нижележащий протокол — см.
[`identity-model.md`](identity-model.md).

---

## 1. Два режима: **LB** vs **Messenger**

Поведение multi-device управляется
[`InstanceTag`](../../crates/veil-proto/src/recipient.rs), который
выбирает отправитель, адресуясь к вашей identity:

| Tag | Смысл | Use case |
|-----|---------|----------|
| `InstanceTag::Any` | "Любое одно активное instance" | Балансировка нагрузки между сервис-флотом |
| `InstanceTag::All` | "Все активные instance'ы" | Multi-device messaging |
| `InstanceTag::Specific(id)` | "Именно это instance" | Targeted доставка / продолжение session'а |

Одна identity может хостить **оба** режима: потребительский
мессенджер использует `All` для user-to-user чатов, в то время как
бизнес-интеграция на той же identity использует `Any` для флота
mail-server instance'ов.

---

## 2. Введение в instance

**Instance** — это один veil-процесс на одном устройстве. У него
есть:

- 16-байтный random **`instance_id`**, persisted в
  `~/.config/veil/instance_id` при первом старте. Стабилен в
  течение жизни устройства — переживает перезагрузки, ротации
  identity, восстановления master-seed'а.
- Свой Ed25519 **`identity_sk`**, master-сертифицированный отдельно
  от ключа каждого другого instance'а. Компрометация `identity_sk`
  одного устройства требует revoke только *этого* subkey'я.
- Свой ML-KEM-768 **encryption keypair**, сертифицированный под
  собственным `identity_sk` instance'а.
- Позиция в общем **`IdentityRegistry`**, который каждый peer
  достаёт перед маршрутизацией сообщения.

```
             identity_id (стабильный)
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
 identity_keys[0]  [1]             [2]
 bound:            bound:          bound:
  laptop           phone           server-farm
  instance_id_A    instance_id_B   instance_id_C
     ▲                 ▲               ▲
  sig_sk_A          sig_sk_B        sig_sk_C
  mlkem_A           mlkem_B         mlkem_C
```

Identity — это просто дерево выше. Добавление устройства наращивает
лист. Revoke устройства подрезает один лист, не затрагивая собратьев.

---

## 3. Добавление устройства — церемония pairing'а

```
          Primary-устройство                       Новое устройство
          (с master_seed)                          (свежая установка)

          $ veil-cli identity pair-invite                    │
            ↳ pair_secret сгенерирован                       │
            ↳ PairingInvite опубликован                      │
            ↳ QR отображён: veil:pair?id=X&secret=Y          │
            ↳ Показан OOB 6-значный код: "123-456"           │
                                                             │
                                              сканировать   ◄┤
                                                       QR    │
                                                             │  подключение напрямую
                                                             │  к источнику через `secret`
                                 ┌──────────────────────►    │
                                 │                           │
                                 │                           │  target генерирует
                                 │                           │  свежий identity_sk
                                 │                           │  (master_seed НИКОГДА
                                 │                           │   не передаётся)
                                 │                           │
          source разлочивает    ◄┤                           │
          master                                             │
          master_sk сертифицирует                            │
          target'ский identity_sk:                           │
            IdentityKey {                                    │
              pubkey: target_pk,                             │
              bound_instance_id: target_id,                  │
              master_sig: ...                                │
            }                                                │
          Дописано в                                         │
          IdentityDocument.                                  │
          Republished.          ─────────────────────────►   │
                                                             │
          OOB-проверка: source показывает "Target: XXX-XXX?" │
                       target показывает тот же              │
                       детерминированный код, выведенный     │
                       из session-ключа                      │
          Пользователь визуально сравнивает,                 │
          подтверждает на source. ──────────────────────►    │
                                                             │
                                 InstanceEntry target'а   ◄──┤
                                 дописан в                   │
                                 InstanceRegistry.           │
                                                             │
                                 DeviceLinkedEvent           │
                                 push'ится существующим      │
                                 instance'ам.                │
```

**Ключевые свойства безопасности**:

- `master_seed` никогда не покидает primary. Новое устройство
  генерирует свой `identity_sk`, который только master может
  сертифицировать — так что даже скомпрометированное новое
  устройство не сможет сертифицировать дальнейшие устройства.
- OOB confirmation-код побеждает атаку "fake target скан'ит QR от
  легитимного primary" — реальный target должен показать реальный
  код. Атакующий, перехвативший QR, выдаст другой session-ключ и,
  следовательно, другой код.
- `pair_secret` имеет 5-минутный TTL и one-time-use.

**CLI-поток** (фактические команды, которые набирает пользователь):

На primary, чтобы напечатать invite-URI + QR (`--endpoint`
обязателен, чтобы новое устройство знало, куда dial'иться обратно):
```bash
veil-cli identity pair-invite --ttl-secs 300 --endpoint tcp://HOST:PORT
# QR отрисован + OOB-код показан.
```

Для интерактивной церемонии accept-and-certify — bind listener'а,
приём dial-back'а, OOB-сравнение и master-сертификация нового
subkey'я — используйте `pair-listen`:
```bash
veil-cli identity pair-listen --endpoint tcp://HOST:PORT
# Bind'ит listener, печатает URI + QR, выполняет source-сторону.
```

На новом устройстве (сканирующий телефон) — отсканированный URI
является **позиционным** аргументом (не `--qr`):
```bash
veil-cli identity pair-accept <veil:pair?…-url>
# Показывает OOB-код — пользователь визуально сравнивает с primary.
# Если коды совпадают, пользователь тапает "confirm" на primary.
```

OOB-сравнение визуально — дефолтный интерактивный путь на обеих
сторонах; `--yes-i-compared-codes` существует, чтобы пропустить
prompt только в скриптовых тестах.

В пределах 60–90 секунд новое устройство полностью live.

---

## 4. Удаление устройства

> ⚠️ **CLI-команды `identity revoke` пока не существует.** Сегодня
> revocation — это операция уровня протокола: master-держатель
> редактирует и republish'ит `IdentityDocument` — отдельного
> subcommand'а под `veil-cli identity` нет (варианты:
> `create`, `show`, `rotate`, `restore`, `claim-name`, `qr`,
> `pair-invite`, `inspect-uri`, `pair-listen`, `pair-accept`,
> `export-qr-backup`, `import-qr-backup`, `standalone`,
> `delegate-device`, `migrate`, `dht-key`, `name-dht-key`).

### 4.1. Механизм

Чтобы удалить устройство, master-держатель добавляет `identity_sk`
этого устройства (subkey из `IdentityDocument.identity_keys`, к
которому оно привязано) в набор `revoked_keys` документа, бампает
`document_version`, переподписывает и republish'ит обновлённый
`IdentityDocument`. У identity не более `MAX_IDENTITY_KEYS = 8`
живых subkey'ев, так что документ остаётся компактным. Как только
peer достанет новый документ, он отвергает будущие кадры,
подписанные revoked'нутым subkey'ем. Устаревший `InstanceEntry`
вытесняется из registry на следующем republish.

### 4.2. Распространение

Переопубликованный документ доходит до peer'ов через DHT republish
(worst-case ≈ DHT TTL, часы) и через gossip / прямой push при
восстановлении session'ов (секунды для подключённых в данный момент
peer'ов). Отдельных флагов `scheduled` vs `compromise` сегодня нет;
разница в срочности чисто операционная — для скомпрометированного
устройства republish'ите немедленно и полагайтесь на gossip, а не
ждите следующего планового republish-тика.

---

## 5. Семантика доставки сообщений

### 5.1. Messenger-режим (`InstanceTag::All`)

Отправитель шифрует **один раз на каждое активное instance**
(fan-out): достаёт каждый `MlKemKeyCert` в registry получателя,
производит один `FanoutEnvelope` на cert. Каждый envelope несёт
instance_id плюс ML-KEM ciphertext + AEAD ciphertext; каждый
envelope расшифровывается под decapsulation-seed'ом ровно одного
устройства ML-KEM.

```
Sender                              Recipient identity @alice
   │
   │  fanout_encrypt(plaintext, certs=[A,B,C])
   │     → [env_A, env_B, env_C]
   │
   │─────── DELIVERY_FORWARD ─────────►  Ноутбук Алисы    (instance A)
   │                                     Телефон Алисы    (instance B)
   │                                     Десктоп Алисы    (instance C)
   │
   │  Каждое устройство:
   │    - выбирает envelope, чей instance_id == self
   │    - decapsulate'ит ML-KEM под собственным seed'ом
   │    - расшифровывает plaintext
   │    - доставляет в application-слой
```

- **Mailbox** хранит offline-копии с ключом по получателю
  (`receiver_id`), отвязанные от `InstanceEntry` — нет ни
  per-instance ACK-cursor'ов, ни параметра `instance_stale_after`.
  Blob'ы живут под первичным ключом `(receiver, content_id)`; GC
  управляется eviction-индексом с ключом
  `(deposited_at_be || receiver || content_id)` плюс per-sender и
  глобальной байтовыми квотами. Под давлением квоты вытесняются
  самые старые deposit'ы (сначала blob'ы анонимного пула, затем
  идентифицированный пул); доставленные blob'ы удаляются на ACK.
- **X3DH one-time prekeys** включаются, когда получатель полностью
  offline. Отправитель выбирает неиспользованный prekey из
  опубликованного пула получателя, encapsulate'ит к этому prekey'ю
  вместо long-lived ML-KEM cert'а, и prekey потребляется при первой
  расшифровке — forward-secrecy для асинхронных сообщений.

### 5.2. Load-balancing режим (`InstanceTag::Any`)

Veil выбирает *одно* из активных instance'ов на основе
опубликованного `InstanceEntry.last_seen_unix_ms` + локального
reputation-score'а. Производится ровно один ciphertext; ровно одно
instance его decapsulate'ит.

Типичное использование: email-gateway identity `@mailserver` с 3
региональными instance'ами. Клиенты шлют на `mailserver:Any`;
veil маршрутизирует в тот регион, у которого минимальная latency
от отправителя.

### 5.3. Targeted-режим (`InstanceTag::Specific`)

Используется, когда session уже приземлился на конкретный instance,
и последующие пакеты в том же разговоре должны держаться того же
instance'а (session continuity). Дедупликация session keys'ится на
`(identity_id, instance_id)`, так что два instance'а одной identity
могут независимо поддерживать session'ы с одним peer'ом.

---

## 6. Что публикует `InstanceRegistry`

Текущий `InstanceEntry` несёт только `instance_id`,
`bound_identity_key_idx`, `label` и `last_seen_unix_ms` — полей
`mailbox_anchor`, `transports` и `encrypted_contact` нет. Прежнее
разделение Tier-A / Tier-B (и config-блок
`[identity.multi_device.tier_b]`) **больше не существует**:
Tier-B encryption-слой удалён вместе с `mailbox_anchor` и
`encrypted_contact`. Transport-хинты теперь ходят out-of-band через
gossip `SignedTransportAnnouncement`, а не встроены в registry, так
что пассивный DHT-наблюдатель, скрейпящий `InstanceRegistry`, не
видит anchor'ов или transport-endpoint'ов для корреляции — только
число устройств, непрозрачные `instance_id`'ы и выбранные оператором
label'ы. Wire-формат — см. [`identity-model.md`](identity-model.md).

---

## 7. Репутация: identity-wide, не per-device

Репутация keys'ится по `identity_id`. Каждое instance вносит вклад и
пользуется общим score'ом. Это by design: флот mailserver-instance'ов
под одной identity строит репутацию вместе; атакующий, скомпрометировавший
`identity_sk` одного устройства, не может независимо испортить
репутацию identity, потому что pipeline revocation удаляет этот ключ
из сети раньше, чем ущерб накопится.

---

## 8. Sync app state (отложено)

> 🚧 **Статус:** только дизайн — примитив `AppState` ещё не
> реализован как конкретный тип. Описанный ниже механизм — целевая
> форма; сегодня приложения, которым нужен cross-device sync,
> используют ad-hoc DHT-слоты под собственной схемой app-key.

Контакты, block-list, preferences, профиль — всё, что приложение
хочет синкать между устройствами пользователя — будет ехать на
примитиве `AppState`: один DHT-слот на кортеж `(identity_id, app_id,
key)`, зашифрованный под общим `app_state_secret` identity и
подписанный любым активным `identity_sk`.

Каждое связанное устройство может читать и писать. Version-
monotonic — out-of-order обновления отбрасываются. Лимит: 4 KB на
blob; партиционируйте app state по нескольким ключам, если нужно
больше.

---

## 9. FAQ

**В:** Могут ли два instance'а моей identity работать одновременно
на одном IP?

**О:** Да. У них разные `instance_id`'ы, поэтому дедупликация
session держит их соединения раздельными. Peer'ы просто видят два
активных instance'а за одной identity.

**В:** Могу ли я расшарить `identity_sk` между двумя устройствами,
чтобы не пэйрить их?

**О:** Нет. У каждого instance'а свой `identity_sk` by design.
Pairing существует именно для того, чтобы ни один ключ не был
расшарен. Это держит blast radius компрометации в точности на одном
устройстве.

**В:** Сколько устройств я могу связать?

**О:** 16 — лимит `IdentityRegistry`. Для больших флотов —
шардируйте по нескольким identity.

**В:** Что произойдёт, если я revoke ноутбук, а телефон офлайн
неделю?

**О:** Телефон всё ещё будет принимать сообщения, адресованные
именно ему. Когда он переподключится, он достанет последний
`IdentityDocument`, заметит, что его собрат revoked'ed, и покажет
оператору алерт в стиле DeviceLinkedEvent. Ваше имя, репутация и
его собственный identity_sk не тронуты.

**В:** Что, если мой телефон скомпрометирован, пока ноутбук
офлайн?

**О:** Revoke subkey телефона с ноутбука, когда он вернётся в
онлайн. Пока revocation не дойдёт до данного peer'а (через DHT
republish или прямой push при восстановлении session'ов), этот peer
может ещё принимать кадры от ключа телефона. Ожидаемое
worst-case распространение: DHT TTL (часы). С gossip ближние peer'ы
подбирают это за секунды.

---

## См. также

- [`identity-model.md`](identity-model.md) — спецификация протокола.
- [`recovery.md`](recovery.md) — восстановление после потери
  устройства или компрометации ключа.
- [`messenger-dev.md`](messenger-dev.md) — построение мессенджера,
  использующего эти примитивы.
