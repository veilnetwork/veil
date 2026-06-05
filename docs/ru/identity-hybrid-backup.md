# Operator Runbook — гибридный identity-backup и восстановление

Этот runbook описывает operator-side workflow для post-quantum
гибридного алгоритма identity (`ed25519+falcon512`): как создать
гибридную identity, что бэкапить и как восстановить её на свежей
машине. Прочитайте это **до** запуска `veil-cli identity create
--algo hybrid` в продакшене.

> **TL;DR**: гибридные identity требуют **двух** независимых
> бэкапов — бумажную BIP-39 фразу **и** файл keypair'а
> `master_falcon.bin`. Потеряете любой из них — identity нельзя
> будет восстановить как гибридную; `node_id` изменится.

## Зачем два бэкапа

Гибридный master-ключ — это два keypair'а, склеенные вместе:

| Половина | Алгоритм | Откуда восстанавливается |
|---|---|---|
| Классическая | Ed25519 | BIP-39 бумажная фраза (24 слова) |
| Post-quantum | Falcon-512 | Только файл `master_falcon.bin` |

BIP-39 фраза детерминированно воспроизводит Ed25519-половину.
Falcon-512 половина генерируется заново из `OsRng` в момент create;
для Falcon-512 нет пути seed-деривации (текущий crate
pqcrypto-falcon его не предоставляет), поэтому единственный способ
сохранить Falcon-половину — держать on-disk файл.

`node_id` это `BLAKE3(ed_pk(32) || falcon_pk(897))` = хэш 929 байт.
Потеряете Falcon-половину — не сможете воспроизвести исходный
929-байтный гибридный pubkey, что означает: restore вынужден будет
fallback'нуться к свежему Falcon keypair'у — выдав **другой**
`node_id`. Ваша регистрация @name, контакты и репутация привязаны к
старому `node_id` и будут потеряны.

## Шаг 1: создать гибридную identity

```bash
veil-cli identity create \
    --algo hybrid \
    --label my-laptop \
    --veil-dir /var/lib/veil
```

CLI выводит 24-словную BIP-39 фразу в stdout и пишет:

```
/var/lib/veil/
├── identity_document.bin     # 1860 B — подписанный sovereign-документ
├── device_identity_sk.bin    # 32 B   — per-device Ed25519 subkey
├── instance_id               # 16 B   — per-device label binding
└── master_falcon.bin         # 2191 B — гибридный master Falcon SK + PK
                              #          (framed bundle "OFAM")
```

Проверить через:

```bash
veil-cli identity show --veil-dir /var/lib/veil
# master_algo:        ed25519+falcon512
# (master_pubkey — 929 байт, подразумевается по master_algo)
```

## Шаг 2: забэкапить ОБА артефакта

### 2a. BIP-39 фраза (бумага)

Фраза печатается один раз в момент create и больше никогда. Запишите
её на бумагу, выбейте на металле или иначе сохраните offline:

```
1.  large       2.  decline     3.  palace      4.  grunt
5.  tired       6.  track       7.  tent        8.  sphere
9.  test        10. era         11. clinic      12. fortune
13. require     14. unfold      15. cluster     16. flat
17. robot       18. eagle       19. scale       20. step
21. decorate    22. banner      23. sausage     24. label
```

НЕ сохраняйте фразу в hot-файл, если только дополнительно её не
шифруете (`--password-file` запишет `master.enc` за вас, но тогда
сам пароль становится единой точкой отказа — выбирайте этот вариант
только если понимаете trade-off).

### 2b. `master_falcon.bin` (цифровой)

Этот файл — **2191 байт** непрозрачных бинарных данных, начинающихся
с ASCII magic `OFAM`. Проверка:

```bash
xxd /var/lib/veil/master_falcon.bin | head -1
# 00000000: 4f46 414d 0100 0005 01...
#           O F A M  ver 1   sk_len=1281 (0x501)
```

Рекомендованное хранение:
- **2-of-3 избыточность** на независимых носителях — например,
  зашифрованный USB-stick, air-gapped вторая машина и зашифрованный
  cloud-storage bucket;
- **Тот же класс защиты, что и BIP-39 фраза** — любой, у кого есть
  этот файл плюс фраза, имеет полный PQ-контроль над вашей identity;
- **Периодически проверяйте**, что файл всё ещё читается И всё ещё
  парсится (используйте `veil-cli identity show` на копии).

> Операторы иногда относятся к Falcon-файлу как к "менее критичному",
> чем BIP-39 фраза, потому что фраза сама по себе восстанавливает
> _что-то_. **Не надо.** Гибридная identity, восстановленная без
> Falcon-файла, на network-слое уже не та же identity — `node_id`
> другой, и каждая claim'нутая запись имени, контакт и routing-
> запись, привязанные к старому `node_id`, становятся orphan'ами.

## Шаг 3: восстановить на свежей машине

После потери устройства, на чистой машине:

```bash
veil-cli identity restore \
    --algo hybrid \
    --phrase-file /path/to/recovered_phrase.txt \
    --master-falcon-file /path/to/recovered_master_falcon.bin \
    --label new-laptop \
    --veil-dir /var/lib/veil
```

Проверить, что восстановленный `node_id` совпадает с исходным:

```bash
veil-cli identity show --veil-dir /var/lib/veil
# node_id: <должно совпадать со значением, выданным `identity create`
#          на исходной машине>
# master_algo: ed25519+falcon512
```

Если `--master-falcon-file` пропущен при гибридном restore, CLI
fail'ится сразу:

```
restore: --algo=hybrid requires --master-falcon-file pointing at the
preserved master_falcon.bin (the BIP-39 phrase alone cannot recover
the post-quantum half — see docs/identity-hybrid-backup.md)
```

Это сделано намеренно; нет тихого degrade-пути к Ed25519-only,
потому что это сменило бы `node_id` без предупреждения.

## Шаг 4: ротация между алгоритмами (`identity migrate`)

Если стартуете с классической Ed25519 identity и хотите апгрейднуть
до гибридной (или наоборот), workflow это **migration**, не restore.
Доступно как `veil-cli identity migrate`.

### 4a. Создать новую identity

На любой машине:

```bash
veil-cli identity create --algo hybrid \
    --veil-dir /var/lib/veil-new \
    --label new-master
```

Это печатает свежий `node_id`. Сохраните новую BIP-39 фразу **и**
новый `master_falcon.bin` (та же backup-дисциплина, что в шаге 2).

### 4b. Выпустить migration cert

На машине, у которой есть доступ И к СТАРОМУ veil_dir, И к
СТАРЫМ master-секретам (BIP-39 фраза ИЛИ пароль от `master.enc`,
плюс СТАРЫЙ `master_falcon.bin`, если СТАРАЯ identity была hybrid /
Falcon-only):

```bash
veil-cli identity migrate \
    --from /var/lib/veil-old \
    --to /var/lib/veil-new \
    --from-phrase-file /path/to/old_phrase.txt
```

(Добавьте `--from-master-falcon-file /path/to/old_master_falcon.bin`,
если СТАРАЯ identity была hybrid или standalone Falcon.)

Вывод:

```
migration cert minted: 1024 bytes
  old_node_id:     <hex>  (algo=ed25519)
  new_node_id:     <hex>  (algo=ed25519+falcon512)
  issued_at_unix:  ...
  valid_until_unix:...   (окно 604800 с)
  cert written к: /var/lib/veil-new/migration_cert.bin
  dht_key:         <hex>

Next step: a running daemon serving --to will publish this cert на
its next maintenance tick.  Or run `node dht put <dht_key> <cert_path>`
against an admin socket для immediate propagation.
```

### 4c. Публикация

Два варианта:

1. **Daemon-driven** (рекомендуется) — запустить daemon, указав
   `--to /var/lib/veil-new`. На своём следующем тике DHT
   republish он подберёт `migration_cert.bin` и опубликует и новый
   IdentityDocument, И MigrationCert.
2. **Вручную** — `veil-cli node dht put <dht_key> <cert_path>`
   через работающий admin-сокет для немедленного распространения.

После публикации текущие resolver'ы автоматически подбирают
цепочку — `resolve_identity_verified(old_node_id)` возвращает НОВУЮ
identity, с защитами от cycle/depth/non-downgrade, описанными в
`crates/veil-identity/src/resolver.rs`.

### 4d. Defence-in-depth: запрет на security-downgrade

CLI-команда `migrate` (и нижележащая
`migration::sign_migration_cert`) **отвергает** любую ротацию,
понижающую security-tier:

| OLD → NEW | Статус |
|---|---|
| ed25519 → ed25519 | OK (refresh-only) |
| ed25519 → falcon512 | OK (PQ upgrade) |
| ed25519 → hybrid | OK (PQ upgrade, рекомендовано) |
| falcon512 → hybrid | OK (вернуть BIP-39 путь) |
| falcon512 → ed25519 | **REJECTED** (PQ → классика = downgrade) |
| hybrid → ed25519 | **REJECTED** (теряем Falcon-компонент) |
| hybrid → falcon512 | **REJECTED** (теряем Ed25519-компонент) |

Порядок tier'ов: `ed25519 (1) < falcon512 (2) < ed25519+falcon512 (3)`.

Попытка downgrade'а fail'ится в момент sign со:

```
migrate: sign_migration_cert: security downgrade rejected
(old_algo=3, new_algo=1)
```

Это defence-in-depth проверка: даже если resolver-side проверку
обойти (например, out-of-band инжектом cert'а), сам `sign`
отказывается произвести cert blob.

## Шаг 5: forensics — что делать, если Falcon-файл потерян

Если BIP-39 фраза уцелела, но `master_falcon.bin` уничтожен, у
оператора два варианта:

1. **Выпустить новую гибридную identity** (`identity create --algo
   hybrid`) и опубликовать MigrationCert со старого гибридного
   `node_id` на новый. Сам cert должен быть подписан старым
   master'ом, что требует потерянного Falcon-файла — поэтому этот
   путь открыт **только**, если Falcon-файл потерян недавно и у вас
   ещё есть работающий live-процесс, держащий master в памяти. Если
   живого процесса нет — цепочка разорвана.

2. **Выпустить новую Ed25519-only identity** (`identity create`, без
   `--algo`), используя BIP-39-восстановленный seed для ОДНОЙ
   половины, принять, что новый `node_id` отличается
   (BLAKE3(32 B) ≠ BLAKE3(929 B)), и заново отстроить ваше @name и
   контакты с нуля. Это "lost everything" recovery — единственный
   технически возможный путь, когда Falcon-материал утрачен
   безвозвратно.

BIP-39 фраза одна **не достаточна** для гибридного восстановления.
Относитесь к двум бэкапам как к единой recovery-паре.

## Краткая шпаргалка

| Нужно | Файл(ы) |
|---|---|
| Подцепить второе устройство под той же identity | `master_falcon.bin` + BIP-39 фраза |
| Восстановиться после потери устройства | `master_falcon.bin` + BIP-39 фраза |
| Расшифровать `master.enc`, если был указан `--password-file` при создании | пароль (хранится отдельно) |
| Найти локальный `instance_id` для диагностики | `<veil_dir>/instance_id` |

## Приложение A: standalone `--algo=falcon512`

Standalone Falcon-512 (`--algo=falcon512`) поддерживается, но **не
рекомендуется для продакшена**. Прочитайте этот раздел до того, как
думать о нём.

### Что это такое

Чистый post-quantum master keypair. **Никакой** классической
Ed25519-компоненты, **никакого** BIP-39 пути backup'а на бумагу, и
**никакого** канала восстановления кроме `master_falcon.bin`.

```
node_id   = BLAKE3(falcon_pk(897 B))    // отличается от hybrid (BLAKE3(929 B))
master_pubkey = falcon_pk(897 B)
master_sk     = OsRng-выведенный Falcon-512 SK, живёт ТОЛЬКО в master_falcon.bin
```

### Зачем это может понадобиться

- Pure-PQ деплой без surface'а классических ключей (нет Ed25519 =
  нет CRQC-recoverable артефакта, даже теоретически).
- Предпочтение оператора не иметь BIP-39 фразу как forensic-
  артефакт (фраза ВОССТАНАВЛИВАЕМА, но она же И ЦЕЛЬ).
- Исследование / эксперименты с чисто post-quantum identities.

### Чем это опасно

BIP-39 фраза в гибридном пути существует **именно для того, чтобы
обеспечить канал восстановления на бумажном носителе**. Убрать её —
значит:

- Потеря `master_falcon.bin` = полная потеря identity. Второго
  канала нет.
- Опечатка в пути при backup'е = полная потеря identity.
- Падающий диск, который вы не заметили при backup'е = полная
  потеря identity.
- Украденное устройство с `master_falcon.bin` и без алерта оператору
  = полная компрометация identity (нет варианта "rotate from the
  old phrase").

### Обязательное подтверждение

CLI отказывается выпускать standalone Falcon-512 identity, если
оператор не передал `--accept-no-recovery`:

```bash
veil-cli identity create --algo falcon512 --label foo \
    --accept-no-recovery
```

Без флага команда fail'ится с:

```
create: --algo=falcon512 has NO recovery path — the master Falcon
SK is generated from OsRng и lives ONLY in <veil_dir>/master_falcon.bin.
Loss of that file = TOTAL identity loss с no paper backup.  Pass
--accept-no-recovery to acknowledge, или use --algo=hybrid which
retains BIP-39-recoverable Ed25519 half.  See docs/identity-hybrid-backup.md.
```

### Что выводит `create` для Falcon-512

- Блок 24-словной BIP-39 фразы **подавляется** — он ничего не
  восстанавливает, поэтому его показ был бы введением в заблуждение.
- Громкий блок `!!! WARNING ...` печатается в operator-поток.
- `master_falcon.bin` создаётся в `<veil_dir>` и печатается с
  аннотацией `(PRESERVE — operator-side recovery medium)`.

### Restore

```bash
veil-cli identity restore --algo falcon512 \
    --master-falcon-file /path/to/preserved_master_falcon.bin \
    --label new-host \
    --veil-dir /var/lib/veil
```

`--phrase-file` **не требуется** (и шумно предупреждается, если
передан — файл декодируется для детектирования опечаток, но его
байты не потребляются). Bundle воспроизводит `node_id` byte-for-byte.

### Рекомендация по backup'у

**3-of-3** избыточность. У standalone Falcon-512 нулевой буфер
восстановления; одна плохая копия — это уже на одну плохую копию
больше, чем допустимо. Для каждого backup'а:

1. Проверьте magic-header `OFAM` файла (`xxd | head -1`).
2. Проверьте, что parser успешен (`veil-cli identity show`
   против временного restore-target).
3. Обновляйте по известному расписанию (минимум — раз в квартал).

Если вы не готовы committed'нуться к 3-of-3, **используйте
`--algo=hybrid` вместо этого.** Классическая половина гибридного
пути митигирует ровно те failure-modes, что перечислены в этом
разделе, ценой дополнительных 64 байт подписи на каждом cert'е.

## См. также

- `docs/identity-model.md` — каноничная sovereign-identity
  спецификация (master + делегирования + auto-reissue).
- `docs/recovery.md` — классический (Ed25519-only) поток
  восстановления.
- `docs/SECURITY.md` — operator-side threat model и митигации.
