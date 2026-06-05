# Модель identity в veil

**Статус**: дизайн зафиксирован 2026-04-20.

Это reference-спецификация для слоя суверенной identity в veil:
стабильный `node_id`, master-ключ + per-device subkeys, короткоживущие
делегирования с автоматическим перевыпуском, standalone-режим (одно
устройство) и multi-device под одним master'ом.

## Краткая шпаргалка

```
node_id   = BLAKE3(master_pubkey)              // стабильный, выведен из master pk
device_id = BLAKE3(device_pubkey)              // детерминированный адрес устройства;
                                                  verifier отвергает несоответствие
Delegation = IdentityKey {                     // per-device делегирование
    pubkey,                                     // Ed25519 device pubkey
    device_id,                                  // = BLAKE3(pubkey)
    valid_from_unix,
    valid_until_unix,                           // по умолчанию 7 дней; перевыпуск
                                                //   при half-validity через
                                                //   maintenance tick
    master_sig,                                 // master_sk подписывает cert
}

Standalone-режим:
  master_pk == device_pk                        // устройство И ЕСТЬ master
  ⟹ node_id == device_id == BLAKE3(device_pk)  // одиночное self-signed делегирование
```

**Нет потока revocation**: реакция на компрометацию — короткое окно
`valid_until_unix` (по умолчанию 7 дней) плюс автоматический
перевыпуск при half-validity. Cert скомпрометированного устройства
устаревает в течение ≤ 7 дней даже без действий оператора.

## Цели

1. **Стабильная identity** — `node_id`, который переживает ротацию
   ключей, потерю устройства и восстановление после компрометации.
   После регистрации он постоянен, пока пользователь сам от него не
   откажется.
2. **Свободная регистрация** — любой пользователь с keypair может
   зарегистрироваться. Без gatekeeper'а, без центрального реестра, без
   DNS. Короткая валидность делегирований заменяет rate-limit-by-PoW
   на уровне документа.
3. **Standalone-режим по умолчанию** — пользователи с одним
   устройством (только телефон, только ноутбук) не нуждаются в
   церемонии с master-ключом. Runtime автоматически собирает
   вырожденный `IdentityDocument`, где `master_pk == device_pk`, при
   первом запуске.
4. **Multi-device** — одна identity, много устройств (телефон +
   ноутбук + десктоп). Каждое устройство работает со своим signing-
   ключом, master-сертифицированным на ≤ 7 дней; автоматический
   перевыпуск при half-validity держит долгоиграющие честные
   устройства в актуальном состоянии.
5. **Балансировка нагрузки** — один и тот же `node_id` может
   маршрутизировать к нескольким устройствам по score / RTT /
   last-seen.
6. **Ноль внешнего доверия** — без DNS-верификации, без guardian'ов,
   без social recovery. Только криптография.
7. **Forward secrecy для асинхронных сообщений** — компрометация
   ключей позже не расшифровывает прошлые сообщения (X3DH-style
   pre-keys).
8. **Time-bounded компрометация** — нет in-band канала revocation,
   который надо защищать. Вместо этого у каждого делегирования
   7-дневный `valid_until`, перевыпускаемый master'ом при
   half-validity. Cert скомпрометированного устройства устаревает в
   течение ≤ 7 дней независимо от действий оператора.

## Концептуальная модель

### Multi-device режим

```
master_seed (32 B random, BIP39 24-word backup, cold storage)
     │
     │ HKDF-SHA256(·, "veil.master.v1")
     ▼
 master_sk  ─ подписывает делегирования (~еженедельно через auto-reissue,
     │      ad-hoc на событиях delegate-device + rotate-device)
 master_pk  (Ed25519 по умолчанию; Falcon-512 — opt-in для post-quantum)
     │
     │ BLAKE3(master_pubkey)            ← голый хэш, без domain tag
     ▼
 node_id  [u8; 32]   ← СТАБИЛЕН НАВСЕГДА
     │
     ├── IdentityDocument (DHT-запись)
     │     ├── master_pubkey (plaintext; verifier пересчитывает node_id отсюда)
     │     ├── identity_keys[]  — per-device делегирования (≤ 8), каждое
     │     │                       master-сертифицировано со своим коротким
     │     │                       valid_until_unix (по умолчанию 7 дней)
     │     ├── document_sig активным subkey'ем (sig_key_idx)
     │     └── (нет revocation list, нет master_freshness_sig, нет PoW —
     │           короткая валидность делегирований + частая republish — это
     │           и есть механизм freshness)
     │
     ├── InstanceRegistry (отдельная DHT-запись)
     │     └── подписана любым активным identity_sk
     │
     ├── NameClaim-записи (отдельно на каждое имя)
     │     └── подписаны любым активным identity_sk
     │
     └── PrekeyBundle (X3DH, per-device)
           └── ML-KEM ephemeral + fallback ключи, master-сертифицированы
```

### Standalone-режим

```
device_sk_seed (32 B Ed25519 seed, сгенерирован runtime'ом или из конфига [identity])
     │
 device_sk = master_sk = identity_sk    ← все три — один и тот же ключ
     │
 device_pk = master_pk = identity_pk    ← все три — один и тот же pubkey
     │
     │ BLAKE3(device_pubkey)
     ▼
 node_id == device_id   [u8; 32]        ← коллапсируют; одиночный subkey
                                          покрывает обе роли
     │
     ├── IdentityDocument (DHT-запись)
     │     ├── master_pubkey == identity_keys[0].pubkey
     │     ├── identity_keys[0]: self-signed делегирование
     │     │   (master_sig произведён device_sk'ом, выступающим в роли master)
     │     └── document_sig одиночным subkey'ем
```

Wire-формат не меняется. Внешний наблюдатель не отличит standalone-
документ от только что созданного multi-device документа с одним
делегированием: эквивалентность `master_pubkey ==
identity_keys[0].pubkey` справедлива для обоих.

**Ключевые инварианты**:

- `node_id` меняется **только** при потере master_seed
  (катастрофично, аналогично потере seed'а Bitcoin-кошелька).
- В multi-device режиме: `master_seed` живёт **только на primary-
  устройстве**; другие устройства получают свой независимый
  identity_sk через pairing или `identity delegate-device` с master-
  сертификацией.
- В standalone-режиме: отдельного master_seed нет — device-ключ И
  ЕСТЬ master-ключ. Перевыпуск происходит автоматически каждые
  ~3.5 дня через maintenance tick; действий оператора не требуется.
- Per-device делегирования: компрометация cert'а одного устройства
  естественно истекает в течение ≤ 7 дней даже без действий
  оператора; master просто перестаёт перевыпускать.
- Множество устройств под одним `node_id` — нативный use case
  (load balancing + multi-device мессенджер).
- Дедупликация session по `(node_id, instance_id)` — per-peer.
  `instance_id` — 16-байтная compatibility-прокладка, выведенная
  из `device_id[..16]`; новый код должен предпочитать полный
  32-байтный `device_id`.

## Криптографические примитивы

| Назначение | Примитив |
|---|---|
| Хэш (binding identity, PoW, commitments) | BLAKE3-256 |
| Long-term подпись | Ed25519 (по умолчанию), Falcon-512 или PQ-гибриды Ed25519+Falcon-512 / Ed25519+Falcon-1024 (рекомендуются для долгоживущих identity) |
| Деривация ключа из master_seed | HKDF-SHA256 |
| Симметричное шифрование | ChaCha20-Poly1305 |
| Кодирование backup master_seed | BIP39 (English, 24 слова) |
| Парольный KDF (зашифрованный master-файл) | Argon2id |

Domain-separated signing-контексты предотвращают cross-protocol
подмену подписи. Нет `REVOKE_CONTEXT` или `FRESHNESS_CONTEXT` — нет
in-band revocation, нет отдельной подписи freshness.
Document-level `valid_until_unix` плюс per-key `valid_until_unix` —
единственные механизмы freshness:

```rust
const CERTIFY_CONTEXT: &[u8] = b"veil.certify.v1";
const DOC_SIG_CONTEXT: &[u8] = b"veil.identity_doc.v1";
const PAIRING_INVITE_SIG_CONTEXT: &[u8] = b"veil.pairing_invite.v1";
const PREKEY_BUNDLE_SIG_CONTEXT:  &[u8] = b"veil.prekey_bundle.v1";
```

### Деривация master-ключа

```
master_sk = HKDF-SHA256(
    salt: None,
    ikm:  master_seed,  // 32 байта
    info: b"veil.master.v1",
    len:  32 (Ed25519) или 48 (размер seed'а Falcon-512)
)
```

### Binding node_id

```
node_id = BLAKE3(master_pubkey)        // 32 байта; голый хэш, без domain tag
```

Binding — голый BLAKE3-хэш, совпадает с деривацией
`cfg::NodeId::from_public_key` в runtime'е. В standalone-режиме это
даёт `node_id == device_id == BLAKE3(device_pubkey)` byte-for-byte
для одного и того же pubkey.

Cross-algorithm коллизии (например, Ed25519 pubkey, хэширующийся
в тот же BLAKE3-выход, что и Falcon-512 pubkey) практически
невозможны: BLAKE3 — 256-битный хэш, а algorithm-байт — часть
окружающего `IdentityKey` cert'а, который verifier проверяет
отдельно.

### Binding device_id

Каждое per-device делегирование несёт явное поле `device_id`, и
verifier отвергает любой cert, где binding не выполняется:

```
device_id = BLAKE3(device_pubkey)      // 32 байта; такая же форма, как у node_id
```

Это делает per-device адреса детерминированными и наблюдаемыми с
провода без доверия к отправителю.

## Wire-формат IdentityDocument

DHT-ключ: `BLAKE3("veil.identity_dht.v1" || node_id)`.

Source-of-truth: `crates/veil-proto/src/identity_document.rs`.
Этот раздел воспроизводит layout исключительно для целей
документации.

```
Layout (canonical-байты — все целые big-endian, если не указано иное):
[0..2]       magic = "ID"                     u16 BE ('I'=0x49, 'D'=0x44)
[2]          version = 1                       u8
[3..35]      node_id                           [u8; 32]
[35]         master_algo                       u8 (0=Ed25519, 2=Falcon-512, 3=Ed25519+Falcon-512, 4=Ed25519+Falcon-1024)
[36..38]     master_pubkey_len                 u16 BE
[38..38+L]   master_pubkey                     [u8; L]  (L=32 или 897)
[...]        issued_at_unix                    u64 BE
[...]        valid_until_unix                  u64 BE   (≤ issued_at + 30d)
[...]        sig_key_idx                       u16 BE
[...]        identity_keys_count               u8
[...]        для каждого IdentityKey:          varies (см. ниже)
[last]       document_sig_len                  u16 BE
[last]       document_sig                      [u8; S]
```

**Policy-лимиты** (проверяются на decode):
- `identity_keys_count ≤ MAX_IDENTITY_KEYS = 8`
- `valid_until_unix - issued_at_unix ≤ MAX_FRESHNESS_WINDOW_SECS = 30 дней`
- Общий размер документа ≤ `MAX_IDENTITY_DOCUMENT_BYTES = 16384` байт (16 КиБ,
  жёсткий лимит; рассчитан на полностью провёрнутый Falcon-гибридный документ и
  согласован с лимитом значения DHT)

Документ не несёт ни replay-guard `document_version`, ни
`revocation_seq` / `revoked_keys[]` / `RevocationEntry`, ни
`freshness_hour` / `master_freshness_sig` / document-level
`pow_nonce`, ни `extensions_root`. Митигация — короткая валидность
делегирования; собственный `valid_until_unix` документа —
единственный механизм freshness.

### `IdentityKey` (per-device делегирование)

```
[0]           algo                       u8
[1..3]        pubkey_len                 u16 BE
[3..3+L]      pubkey                     [u8; L]
[...]         device_id                  [u8; 32]   (= BLAKE3(pubkey))
[...]         valid_from_unix            u64 BE
[...]         valid_until_unix           u64 BE     (per-key срок,
                                                     по умолчанию issued_at + 7 дней)
[...]         master_sig_len             u16 BE
[...]         master_sig                 [u8; S]
```

`master_sig` покрывает:
```
CERTIFY_CONTEXT
|| node_id
|| algo
|| len(pubkey) as u16 BE
|| pubkey
|| device_id
|| valid_from_unix
|| valid_until_unix
```

### Подпись документа

`document_sig` покрывает canonical-байты всех полей выше (исключая
сами `document_sig_len` и `document_sig`):

```
DOC_SIG_CONTEXT || canonical_bytes_up_to_doc_sig
```

Подписывается текущим активным identity_sk (на который ссылается
`sig_key_idx`). В standalone-режиме активный subkey И ЕСТЬ master,
так что document_sig и одиночный `IdentityKey.master_sig` произведены
одним и тем же ключом.

## Алгоритм verifier'а

Вход: `doc: IdentityDocument`, `now_unix_secs: u64`.

Source-of-truth: `crates/veil-identity/src/verify.rs`.

1. Magic `"ID"` и version.
2. Пересчитать `node_id = BLAKE3(master_pubkey)`, отвергнуть при
   несовпадении.
3. Проверить `now ≤ doc.valid_until_unix` (окно freshness документа).
4. Для каждого `IdentityKey`:
   - **4a.** `device_id == BLAKE3(pubkey)` (детерминированный
     binding). Отвергнуть `DeviceIdMismatch`.
   - **4b.** `now ≤ key.valid_until_unix` (срок per-делегирования).
     Отвергнуть `KeyExpired`.
   - **4c.** Проверить `master_sig` через `master_pubkey` по
     `CERTIFY_CONTEXT || node_id || algo || len(pubkey) || pubkey ||
     device_id || valid_from || valid_until`.
5. Проверить, что `sig_key_idx` в допустимых границах.
6. Проверить `document_sig` через `identity_keys[sig_key_idx]` по
   `DOC_SIG_CONTEXT || canonical_signing_bytes()`.

Возвращает `ValidatedIdentity {
  node_id,
  master_algo, master_pubkey,
  active_identity_pubkey, active_identity_algo, active_key_idx,
  active_device_id,                  // детерминированный адрес устройства
  active_instance_id,                // compat-прокладка: device_id[..16]
}`.

Verifier не трогает персистентный кэш revocation, не проверяет
document-level PoW и не верифицирует отдельную подпись freshness.

## Операции жизненного цикла

### Genesis — multi-device (`veil-cli identity create`)

1. Сгенерировать `master_seed = OsRng::gen(32)`.
2. Вывести `master_sk`, `master_pk`; вычислить `node_id =
   BLAKE3(master_pk)`.
3. Сгенерировать `identity_sk_0` первого устройства (эфемерный
   random, не выведенный из master).
4. Вычислить `device_id_0 = BLAKE3(identity_pk_0)`.
5. `master_sig_0 = master_sk.sign(CERTIFY_CONTEXT || node_id || algo
   || len(identity_pk_0) || identity_pk_0 || device_id_0
   || valid_from || valid_until)`. По умолчанию `valid_until =
   now + 7 дней`.
6. Собрать IdentityDocument с одной записью IdentityKey.
7. `document_sig = identity_sk_0.sign(DOC_SIG_CONTEXT || canonical)`.
8. Показать BIP39-фразу; пользователь записывает её.
9. Опционально сохранить зашифрованный master-файл (Argon2id +
   ChaCha20-Poly1305).
10. Опубликовать IdentityDocument в DHT (runtime делает это при
    первом старте).

### Genesis — standalone (`veil-cli identity standalone`)

1. Сгенерировать `device_sk_seed = OsRng::gen(32)`.
2. `device_pk = derive(device_sk)`; `node_id = device_id =
   BLAKE3(device_pk)`.
3. Self-signed делегирование: device_sk действует как master_sk.
   `master_sig = device_sk.sign(CERTIFY_CONTEXT || node_id || ... )`.
4. `document_sig = device_sk.sign(DOC_SIG_CONTEXT || canonical)`.
5. Записать `identity_document.bin` + `device_identity_sk.bin`.

Runtime автоматически выполняет шаги 1–5 при первом старте, если
`identity_document.bin` отсутствует, а в конфиге `[identity]` есть
Ed25519 keypair (auto-bootstrap).

### Auto-reissue при half-validity

Maintenance loop крутится на каждом cleanup tick (по умолчанию ~30 с):

1. Прочитать активный `IdentityKey.valid_until_unix`.
2. Если `now + DELEGATION_VALIDITY_SECS / 2 < valid_until` — no-op
   (осталось > половины окна).
3. Иначе, в **standalone-режиме**, runtime переподписывает на месте:
   `master_sk == device_sk == self.identity_sk` уже в памяти. Новое
   `valid_until = now + 7 дней` (снова полное окно).
4. В **multi-device режиме** tick — no-op, так как master_sk живёт
   на другом устройстве. Оператор запускает `veil-cli identity
   delegate-device --pubkey-file ... --validity 7d` с master-
   устройства до истечения текущего делегирования; обновлённый
   документ доставляется (USB / scp / QR) на целевое устройство и
   кладётся в `<veil_dir>/identity_document.bin`. Опрос mtime
   on-change в `runtime/sovereign_republish.rs` (60-секундный
   интервал) подбирает новый документ и republish'ит его в DHT.

### Pairing нового устройства (QR-церемония)

См. реализацию в runtime: `crates/veil-cli/src/cmd/sovereign_identity.rs::{pair_invite,
pair_listen, pair_accept}`.

### Митигация компрометации

**In-band канала revocation нет**. Вместо этого:

1. Оператор перестаёт перевыпускать делегирование
   скомпрометированного устройства (multi-device: просто не
   запускает `delegate-device` для этого pubkey'а; standalone:
   проворачивает device-ключ через `identity standalone --force`,
   если скомпрометирован сам master SK).
2. Скомпрометированный cert устаревает в течение ≤ 7 дней по мере
   прохождения `valid_until_unix`. Verifier'ы отвергают cert (шаг 4b
   `KeyExpired`); peer'ы перестают принимать handshake от этого
   устройства.
3. Long-term session'ы, уже установленные со скомпрометированным
   устройством, продолжаются до достижения собственного session-
   rekey TTL.

Это меняет время реакции (≤ 7 дней vs минут для in-band revoke) на
значительно меньшую поверхность протокола — нет revocation gossip,
нет кэша revocation, нет поля `revoked_keys[]`, нет
`master_freshness_sig`.

## Резолвинг имён

Имена claim'ятся под ASCII-only whitelist `[a-z0-9#_-]`, без учёта
регистра (нормализуются в lowercase до хэширования):

```
name_dht_key = BLAKE3("veil.name_claim_dht.v1" || u16_be(len(name)) || name.as_bytes())
```

Значение NameClaim содержит:
- строку имени
- node_id
- встроенный `cert_proof` (master_pubkey + master_sig по подписывающему
  identity_pubkey) для offline-верификации
- signing_identity_key_idx
- подпись любым активным identity_sk
- PoW-nonce пропорциональный редкости

Resolver достаёт NameClaim → извлекает node_id → достаёт
IdentityDocument → валидирует cert-цепочку → резолвится в
`ValidatedIdentity`.

**Сложность PoW масштабируется по редкости**:
- 1-3 char ASCII буквенные: 28-30 (часы CPU)
- 4-6 символов: 22-26 (минуты)
- 7-12 символов: 18-22 (секунды-минуты)
- С дискриминатором (`alice#1234`): 14 (~1 с)
- Длинный random (`AnonXYZ_7a3bf2`): 12 (~1 с)

## InstanceRegistry

Отдельная DHT-запись, обновляется при online/offline-переходах.
Компактная (как правило < 2 KB). Source-of-truth:
`crates/veil-proto/src/instance_registry.rs`.

```
DHT-ключ = BLAKE3("veil.instances_dht.v1" || node_id)
```

В registry нет блока `tier_b`; `mailbox_anchor` и зашифрованные
contact-хинты — не часть схемы. Transport-хинты живут в gossip
`SignedTransportAnnouncement`. Текущая форма:

```
InstanceRegistry {
    node_id:                  [u8; 32],
    instances:                Vec<InstanceEntry>,   // ≤ 16
    reg_version:              u64,                    // монотонный
    created_at_unix:          u64,
    signing_identity_key_idx: u16,                    // индекс в IdentityDocument
    sig:                      Vec<u8>,                // любой активный identity_sk
}

InstanceEntry {
    instance_id:              [u8; 16],   // обрезанный device_id (compat-прокладка)
    bound_identity_key_idx:   u16,        // → IdentityDocument.identity_keys[i]
    label:                    String,     // ≤ 32 B, опционально
    last_seen_ms:             u64,        // грубая гранулярность
}
```

## Маршрутизация: InstanceTag

Wire-уровень `Recipient`:

```
Recipient {
    node_id:      [u8; 32],
    instance_tag: InstanceTag,
}

enum InstanceTag {
    Any,                    // load-balanced — veil выбирает одно устройство
    All,                    // fan-out broadcast — все устройства
    Specific([u8; 16]),     // direct — точный instance_id (= device_id[..16])
}
```

Примечание: runtime по-прежнему keys'ится на 16-байтном `instance_id`
(обрезание полного 32-байтного `device_id`) для дедупликации session
+ доставки dispatcher'ом.

## Threat-модель

См. [`docs/recovery.md`](recovery.md) и
[`docs/opsec-user-guide.md`](opsec-user-guide.md) — пользовательские
operational-security концерны.

### В скоупе (veil защищает)

- Хайджэк `node_id` через pre-image атаку на BLAKE3 — невозможно
  (2^256).
- Подделка `device_id` — verifier отвергает любой cert, где
  `device_id != BLAKE3(pubkey)` (детерминированный binding).
- Утечка ежедневного `identity_sk` (malware, украденный ноутбук) —
  скомпрометированный cert устаревает в течение ≤ 7 дней, поскольку
  master перестаёт его перевыпускать.
- Сквоттинг имён — PoW, пропорциональный редкости (по-прежнему в
  слое NameClaim).
- Фишинг QR-pairing'а — OOB confirmation-код.
- Flood обновлений документа со скомпрометированного ключа —
  per-identity DHT-квота.
- Eclipse-атака на резолвинг identity — multi-replica quorum.
- Forward secrecy для прошлых async-сообщений — X3DH one-time prekeys.

**Out of scope by design**:
- Реакция на компрометацию быстрее 7 дней. Используй `identity
  standalone --force` (для компрометации master'а на standalone)
  или `identity rotate` + ожидание естественного 7-дневного окна
  (multi-device).
- Stale revocation-атаки. Канала revocation нет; нечему быть stale.

### Вне скоупа (ответственность OpSec пользователя)

- Потеря физического backup'а `master_seed` — identity потеряна
  навсегда (как с seed'ом Bitcoin-кошелька).
- Компрометация хранения master'а (физическая кража бумаги,
  неавторизованный доступ к разблокированному зашифрованному файлу) —
  полный захват, невосстановимо в рамках этой identity. Митигация:
  бумага в банковской ячейке, hardware keys, стойкие passphrase'ы.
- Социальная инженерия (пользователь раскрывает BIP39-фразу) —
  задокументировано в opsec-user-guide.md как предупреждения;
  протокол не может предотвратить.
- Malware на устройстве во время показа BIP39, keylogging паролей —
  ответственность за безопасность устройства.
- Миграция алгоритма при появлении quantum-угрозы — master_algo +
  per-subkey algo позволяют ротацию в Falcon-512 или гибрид
  Ed25519+Falcon-512/1024, но инициирует её пользователь.

## Гибкость алгоритмов

`master_algo: u8` и `IdentityKey.algo: u8` у каждого ключа позволяют
mixed-algorithm деплои. Пользователь может:

- Стартовать с Ed25519-identity.
- Позже добавить Falcon-512 subkey'и (master сертифицирует их).
- В итоге провернуть master в post-quantum алгоритм через
  re-issuance (новый master_sk, новый node_id; имена / репутация
  нуждаются в migration proof или re-claim — будущая работа).

## См. также

- [`docs/recovery.md`](recovery.md) — пользовательский гайд по
  восстановлению после компрометации, потере устройства, best
  practices BIP39.
- [`docs/multi-device.md`](multi-device.md) — LB vs messenger
  режимы, Tier A vs B privacy trade-offs.
- [`docs/opsec-user-guide.md`](opsec-user-guide.md) — чек-лист
  физической безопасности, предупреждения о фишинге.
- [`docs/messenger-dev.md`](messenger-dev.md) — как строить
  мессенджер-приложение на примитивах veil.
