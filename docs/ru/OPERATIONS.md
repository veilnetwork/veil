# Руководство по эксплуатации

> **Парные документы:** [MONITORING.md](MONITORING.md) — за чем смотреть и когда алертить; [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — таблица симптом → причина → fix.

## Быстрый старт

```bash
# Сборка (release)
cargo build --release

# Сгенерировать identity (24-битный PoW майнится — около 30 с на современном CPU)
veil-cli --config node.toml config init

# Запустить узел (foreground; для systemd используйте `node run --foreground`)
veil-cli --config node.toml node run
```

## Конфигурация

Config-файл: формат TOML. Ключевые секции:

| Секция | Назначение | Ключевые поля |
|---------|---------|------------|
| `identity` | Keypair узла + PoW nonce | `algo`, `public_key`, `private_key`, `nonce`, `role` |
| `listen[]` | Transport listeners | `transport` (tcp/tls/quic/ws), `advertise`, `tls_*` |
| `peers[]` | Статический список peer'ов | `peer_id`, `public_key`, `transport`, `nonce` |
| `bootstrap_peers[]` | Discovery seeds (опрашиваются только когда `peers` пуст) | то же что `peers[]` |
| `routing` | Тюнинг gossip + cache | `max_gossip_hops` (2), `reannounce_interval_secs` (30) |
| `session` | Session limits | `max_concurrent` (512), `tx_queue_depth` (4096), `idle_timeout_secs` (90) |
| `dht` | Тюнинг Kademlia | `k` (20), `alpha` (3), `max_store_entries` (25K по умолчанию, opt-up до 1M через cold-tier), `shard_filtering` |
| `mailbox` | Offline-хранилище | `enabled`, `quota_per_receiver_bytes`, `ttl_secs`, `require_capability_token` |
| `metrics` | Prometheus export | `listen` (например `tcp://0.0.0.0:9090`), `path` |
| `[global].admin_socket` | Admin/CLI control plane endpoint | `unix:///path/to/admin.sock` или `tcp://127.0.0.1:0?runtime_dir=...` |
| `[ipc]` | Application-side IPC | `enabled`, `socket_uri` |

Полный справочник: [config-reference.md](config-reference.md).

## Типовые операции

### Start / stop / reload

```bash
# Старт
veil-cli -c node.toml node run

# Статус (использует admin socket из конфига)
veil-cli -c node.toml node show
# → node_id, role, version, build_features, uptime, число sessions/peers/listens

# Reload конфига (применить изменения без сброса сессий где возможно)
veil-cli -c node.toml node reload

# Стоп (SIGTERM); runtime сливает сессии в течение ≤5 с до выхода
kill <pid>          # или `systemctl stop veil-node`
```

### Инспекция peer'ов и сессий

```bash
veil-cli -c node.toml peers list             # configured peers
veil-cli -c node.toml peers banned           # активные баны (manual + temp)
veil-cli -c node.toml sessions list          # короткие id
veil-cli -c node.toml sessions list -v       # полные 64-hex id
veil-cli -c node.toml node dht routing       # содержимое Kademlia k-bucket'ов
veil-cli -c node.toml node dht list          # DHT key-value store
veil-cli -c node.toml node metrics           # снапшот Prometheus-exporter'а
```

### Управление банами

```bash
# Permanent ban (персистится в <config-dir>/bans.json)
veil-cli -c node.toml peers ban <NODE_ID_HEX>

# Снять manual ban
veil-cli -c node.toml peers unban <NODE_ID_HEX>

# Убить сессию по link_id (также ставит 30 с auto-ban, чтобы peer
# не зареконнектился сразу — для краткосрочной митигации; для permanent используйте `peers ban`)
veil-cli -c node.toml sessions kill <LINK_ID_HEX>
```

`peers ban` симметричен на проводе — забанить нужно только одной стороне,
чтобы новые соединения отвергались, но если банят обе стороны, ни одна не
уйдёт в retry-loop.

### Апгрейд бинарника

1. **Соберите новый релиз:** `cargo build --release --features production-seeds`
2. **Положите рядом на хосте:** скопируйте новый `veil-cli` рядом со старым, например `veil-cli.new`
3. **Атомарный swap:** `mv veil-cli.new veil-cli`
4. **Перезапустите:** `systemctl restart veil-node` (или kill + relaunch).
   Персистентное state — баны, DHT-значения, identity, mailbox WAL — переживает рестарт.
5. **Проверьте:** `veil-cli node show` → проверьте, что `version:` соответствует ожидаемому билду.

Wire-протокол (формат сообщений на проводе) на работающем стеке везде один
— OVL1. Два бинарника, отличающиеся только кодом вне формата на проводе
(внутренности маршрутизации, форматирование логов, значения по умолчанию),
полностью совместимы. Скоординированное обновление всего парка узлов не
требуется. Когда меняется сам формат на проводе (следующая major-версия),
следуйте матрице version-skew в [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

## Настройка seed-узла

Seed-узел — это долгоживущий публичный узел. Его `(public_key, transport, nonce)`
жёстко зашиты в `node/bootstrap/seeds.rs::BUILTIN_SEEDS`. Свежий узел, у
которого нет ни `[[peers]]`, ни `bootstrap_peers` в конфигурации, использует
эти seed-узлы, чтобы впервые войти в сеть.

### Pre-deploy чеклист

1. **Подготовьте хост** — публичный IP, открытый inbound TCP порт (default 7001),
   ≥2 CPU / ≥4 GB RAM / ≥10 Mbps sustained, ≥99 % uptime.
2. **Сгенерируйте identity** локально на seed-хосте:
   ```bash
   veil-cli -c /etc/veil/seed.toml config init
   ```
   Это майнит 24-битный PoW nonce (~30 с). Output `identity.public_key`,
   `identity.nonce`, computed `node_id` — всё это понадобится для записи в
   BUILTIN_SEEDS.
3. **Сконфигурируйте listener:**
   ```toml
   listen = [{ id = "0x00000001", transport = "tcp://0.0.0.0:7001" }]
   [identity]
   role = "core"
   ```
4. **Запустите в foreground для первого verification run:**
   ```bash
   veil-cli -c /etc/veil/seed.toml node run
   # смотрите логи на `listen.start`, без ошибок; Ctrl-C чтобы остановить
   ```

### Добавление seeds в бинарник

Отредактируйте `crates/veil-bootstrap/src/seeds.rs`:

```rust
const BUILTIN_SEEDS: &[BootstrapPeer] = &[
    BootstrapPeer {
        transport:    "tcp://seed-1.veil.example:7001",
        public_key:   "BASE64_PUBKEY_FROM_seed.toml",
        nonce:        "BASE64_NONCE_FROM_seed.toml",
        algo:         SignatureAlgorithm::Ed25519,
        tls_cert:     None,
        tls_ca_cert:  None,
    },
    // … ещё 2 или 3, в разных географических зонах / провайдерах
];
```

Соберите все client/seed бинарники с feature-флагом production-seeds:

```bash
cargo build --release --features production-seeds
```

Compile-error guard для release-сборки (`veil/Cargo.toml` + `seeds.rs`)
запорет сборку, если `BUILTIN_SEEDS` пустой И не включены ни
`production-seeds`, ни `allow-empty-seeds`.

### Multi-seed redundancy

- Держите **минимум 3** seed-узла у **разных сетевых провайдеров и в разных
  географических регионах** — потеря одного не должна ломать первичное
  подключение к сети.
- Храните личности seed-узлов в офлайн-хранилище (ноутбук плюс бумажная
  резервная копия). Потеря одной означает пересборку всего парка узлов, а не
  правку на ходу.
- Ротируйте по одному seed-узлу за раз; никогда одновременно.

### `.onion` bootstrap-источник (Tor) — escape-хатч на крайний случай

Когда заблокированы все clearnet-слои bootstrap (CDN-хостнеймы оператора, весь
CDN и DNS), оператор может опубликовать **подписанный seed-бандл** по Tor
`.onion`-адресу, и узлы будут тянуть его через локальный Tor SOCKS-прокси
(deferred backlog 481.4). Разнообразие exit/rendezvous-узлов Tor сводит на нет
блокировку по IP/SNI самого bootstrap-fetch'а.

```toml
[global]
# Любой .onion URL в списке тянется через Tor; clearnet-URL не затронуты и
# по-прежнему идут прямым PKI-verified HTTPS-путём.
bootstrap_https_urls = [
  "https://cdn1.example/seeds.json",      # clearnet — напрямую
  "http://abcd…xyz.onion/seeds.json",     # через Tor
]
# Локальный Tor SOCKS5-эндпоинт. Обязателен для .onion URL выше; если не задан —
# .onion URL пропускается (логируется), clearnet-URL не затронуты.
bootstrap_tor_socks_proxy = "socks5://127.0.0.1:9050"
# Пин издателя бандла (настоятельно рекомендуется) — см. «подписанные бандлы».
trusted_bundle_issuer_pubkey = "<base64 issuer pubkey>"
```

**Почему plain `http://`, а не `https://`.** `.onion`-адрес *и есть* публичный
ключ сервиса — подключение к нему доказывает (через Tor rendezvous), что вы
достигли его владельца, а Tor-цепочка уже зашифрована. Сертификата публичного
CA для верификации нет, поэтому TLS ничего не добавил бы. Аутентичность даёт
**подписанный бандл**, который на `.onion`-пути требуется **безусловно**: сырой
JSON отвергается даже при `legacy_allow_unsigned_bootstrap = true`. (URL вида
`https://…onion` отклоняются.)

**Настройка.**
1. Запустите Tor (`apt install tor`; клиентский SOCKS по умолчанию на
   `127.0.0.1:9050`). На хосте, отдающем бандл, добавьте `HiddenServiceDir` +
   `HiddenServicePort 80` на ваш статический файл-сервер и прочитайте
   сгенерированный `hostname`.
2. Подпишите seed-бандл (bundle-signing в `veil-cli`) и отдавайте подписанные
   байты по `http://<onion>/seeds.json`.
3. Добавьте `.onion` URL, `bootstrap_tor_socks_proxy` и
   `trusted_bundle_issuer_pubkey` в конфиги клиентов.

**Верификация.** `journalctl -u veil-node | grep bootstrap.https` — рабочий
`.onion`-источник логирует `bootstrap.https.found N seed(s) from http://…onion…`;
отсутствие прокси — `bootstrap.https.fetch_failed … set [global]
bootstrap_tor_socks_proxy`.

**Границы.** `.onion`-хост передаётся прокси как SOCKS5 domain-адрес и
резолвится Tor'ом — никогда локально (нет DNS-утечки). Fetch ограничен тем же
10-секундным таймаутом и 64 KiB-кэпом ответа, что и clearnet-путь.

### Пример systemd unit

```ini
[Unit]
Description=Veil seed node
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=veil
Group=veil
ExecStart=/usr/local/bin/veil-cli -c /etc/veil/seed.toml node run --foreground
Restart=always
RestartSec=5
LimitNOFILE=65536
# Разрешить демону mlock'ать аллокации секретных ключей (session AEAD keys,
# session_kdf OKM, identity_sk).  Без этого ключевой материал может попасть
# в swap на диск под давлением памяти — см. секцию «Memory locking» ниже.
LimitMEMLOCK=infinity
# Чтобы state оставался writable
ReadWritePaths=/var/lib/veil /run/veil

[Install]
WantedBy=multi-user.target
```

В `/etc/veil/seed.toml` следует выставить `[global].admin_socket =
"unix:///run/veil/admin.sock"`, чтобы `veil-cli` работал без `-c`
(когда у пользователя есть read-доступ к сокету).

## Memory locking (RLIMIT_MEMLOCK / CAP_IPC_LOCK)

Начиная с Этапа 6, демон закрепляет в оперативной памяти каждый выделенный
секретный ключ вызовом `mlock(2)` — это системный вызов, который не даёт
странице памяти уйти в swap (область подкачки на диске). Так защищены
session AEAD keys, промежуточный session_kdf OKM и — через последующие
слайсы — identity_sk, master_seed и кэш peer_mlkem. Цель — закрыть вектор
утечки через swap. Без этого атакующий, получивший позже физический доступ
к диску, мог бы восстановить ключи из swap спустя минуты-дни после закрытия
сессии.

mlock'нутые регионы дополнительно помечаются `MADV_DONTDUMP`
(Linux) или `MADV_NOCORE` (FreeBSD / NetBSD), исключая их из
process core dump'ов, которые systemd-coredump и ему подобные иначе
захватили бы под `/var/lib/systemd/coredump/` при панике.
В macOS нет эквивалентного madvise-advisory — операторам, обеспокоенным
exposure'ом при крэше на Darwin, следует выставить `launchctl limit
core 0`, чтобы подавить cores process-wide.

### Требуемые лимиты

| Окружение | Что выставить | Зачем |
|---|---|---|
| systemd unit | `LimitMEMLOCK=infinity` (или большой явный cap, напр. `268435456` для 256 MiB) | Дефолтный Linux ulimit — 64 KiB на процесс; демону нужно больше для сессий под устойчивым трафиком |
| Shell-launched debug | `ulimit -l unlimited` перед `veil-cli node run` | Та же причина; per-shell |
| Docker / Podman | `--ulimit memlock=-1:-1` или `--cap-add=IPC_LOCK` в `docker run` | Контейнеры по умолчанию сбрасывают `CAP_IPC_LOCK`; без него mlock() падает с EPERM независимо от RLIMIT_MEMLOCK |
| Kubernetes | `securityContext.capabilities.add: ["IPC_LOCK"]` + соответствующая ulimit-конфигурация kubelet | То же обоснование, что и для Docker |

### Операционная видимость

Демон НЕ падает при сбое mlock. Вместо этого он логирует
**once-per-process** warn:

```
WARN  veil_util.sensitive_bytes.mlock_fallback
      mlock failed on key allocation, falling back to zeroize-only
      (bytes are still wiped on drop, but pages may swap to disk).
      Raise RLIMIT_MEMLOCK or grant CAP_IPC_LOCK to close swap exposure.
```

Скрейпьте эту лог-строку — её присутствие на продакшен-узле означает,
что гарантия безопасности, которую поставляет Этап 6, была **молча
деградирована** до до-Этап-6 baseline (только zeroize-on-drop, без
защиты от swap'а). Демон продолжает работать корректно; вектор leak'а
снова открыт.

### Верификация

Поднимите узел и подтвердите, что лимит применился:

```sh
$ cat /proc/$(pgrep veil-cli)/limits | grep "Max locked memory"
Max locked memory       unlimited            unlimited            bytes
```

Если вы видите маленькое числовое значение (напр. `65536`),
пересмотрите лимиты systemd unit / контейнера и перезапустите.

### Trade-offs

mlock'нутые страницы не могут быть вытеснены ядерным page reclaimer'ом —
они навсегда учитываются против бюджета физической RAM хоста. Для
типичного veil-relay, несущего 100-1000 одновременных сессий,
mlocked-footprint составляет **96 B × session_count** для OKM-derivation
промежуточных значений (function-scope; освобождаются после возврата
из функции) плюс будущие per-session AEAD key sites (follow-up слайсы
Этапа 6). Relay, несущий 10000 сессий с полным покрытием Этапа 6, занял
бы примерно 1-2 MiB memlock — пренебрежимо мало относительно общего RSS
демона.

НЕ выставляйте `LimitMEMLOCK=infinity` на хостах с ограниченной памятью
(< 256 MiB суммарной RAM, напр. некоторые развёртывания Raspberry Pi
Zero). На таких хостах туго-ограниченное явное значение
(`LimitMEMLOCK=16384` = 16 MiB) оставляет headroom для рабочего набора
демона, всё ещё покрывая большинство аллокаций ключей.

## Config signing (Этап 11)

Начиная со слайса 11a Этапа 11, демон поддерживает подписанные
оператором config-файлы. До подписания любой, у кого есть доступ на
запись в файловой системе, мог флипнуть
`legacy_allow_unsigned_bootstrap = true`, понизить
`anycast.resolve_policy` с `signed_only` до `best_effort`,
перенаправить bootstrap peers и т.д. — без перезапуска демона.
Подписанный config делает байт-уровневую поверхность tamper'а
структурированным WARN-логом; setup с pinned-issuer дополнительно
вскрывает tamper «wrong issuer».

### Подпись config-файла

Используйте активный keypair `[identity]`, чтобы подписать файл in place:

```sh
veil-cli -c /etc/veil/config.toml config sign
# → эмитит INFO-строку с fingerprint'ом issuer-pubkey и issued_at;
#   атомарно переписывает файл с комментарием-заголовком
#   `# VEIL_CONFIG_SIGNATURE_V1: …` наверху.
```

Повторная подпись того же файла заменяет предыдущий signature-заголовок
(идемпотентно). Используйте `--issued-at <UNIX_SECS>`, чтобы встроить
конкретный timestamp (default: `SystemTime::now()`). Используйте
`--stdout` для dry-run (печатает подписанные байты без записи обратно).

Ключ подписи — это keypair `[identity]` оператора, тот же, что
используется для `config publish` бандлов. Никакого отдельного
управления keypair'ом.

### Пиннинг доверенного issuer-pubkey (production hard-fail)

Когда выставлен `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY`, демон
верифицирует подпись против ИМЕННО ЭТОГО pubkey:

```ini
[Service]
Environment=VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY=<base64-encoded-pubkey>
```

Или для shell-launched вызовов:

```sh
VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY=<base64> veil-cli node run
```

Пиннинг закрывает тонкую брешь: в unpinned-режиме демон принимает
ЛЮБУЮ подпись при условии, что envelope внутренне консистентен —
полностью атакующий-изданный config со свежим-но-атакующему-принадлежащим
ключом всё равно прошёл бы. Пиннинг ловит этот вектор.

Пиннинг живёт в env-переменной, а не в самом `config.toml`, потому что
пиннинг внутри config'а — chicken-and-egg: подделанный config мог бы
просто удалить pin. Env-переменные живут в systemd unit / Docker
compose / Kubernetes-манифесте — отдельная trust boundary от
config-байтов оператора.

### Операционная видимость

Скрейпьте эти лог-строки, чтобы мониторить состояние signed-config:

```
INFO  veil_cfg.signed_config
      config '<path>' signature verified (issuer=<fingerprint>…,
      issued_at=<unix_secs>, pinned=true|false)

WARN  veil_cfg.unsigned_config
      config file '<path>' has no signature header; tamper protection
      is OFF.

WARN  veil_cfg.signed_config_verify_failed
      config '<path>' has a signature header but verification failed:
      <structured-error>.  Loading anyway (refusal is opt-in via a
      future `require_signed_config = true` global flag).
      Investigate immediately — possible tamper or stale env-var pin.
```

Алертите на **оба** — `unsigned_config` (drift deployment-config'а;
оператор забыл подписать) и `signed_config_verify_failed` (активный
tamper или ротация pin'а / ключа in-flight без координации).

### Phase 1 vs phase 2 enforcement

Текущее поведение — **phase 1 warn-only**: подделанные config'и всё ещё
загружаются с WARN-логом. Операторы получают grace-окно, чтобы
подписать свои существующие config'и, не ломая развёртывания.

Phase 2 (отдельный будущий слайс) добавляет глобальный флаг
`require_signed_config = true`, который флипает warn-only-путь на
refuse-on-failure. Выставляйте это после того, как каждая машина во
флоте была подписана И верифицирована через dry-run.

### Миграция Этап 11e: per-origin byte cap + unsigned-STORE hard-fail

Слайс 11e (Этап 11e) добавляет две взаимодополняющие ручки hardening'а к
storage-пути DHT:

**1. `[dht] per_origin_max_bytes = N`** — per-signer байтовый бюджет.
Когда выставлен, локальный `TieredStore` отслеживает
bytes-stored-per-signer pubkey, и STORE, который протолкнул бы signer'а
за `N` байт, отвергается на демоне с `PerOriginByteCapExceeded`. Честные
signer'ы обычно держат горстку записей (NameClaim + IdentityDocument +
небольшой fan-out AppEndpointEntry) — 64 KiB это комфортный потолок,
который всё ещё оставляет headroom для легитимного роста. Misbehaving /
Sybil signer'ы больше не могут заполнить store в одностороннем порядке —
они могут заполнить только свой собственный per-origin слайс. Операторам,
которые **явно повторно включили** legacy-путь `allow_unsigned_store =
true` (теперь он по умолчанию `false` — см. ниже), стоит учесть, что все
unsigned legacy-STORE'ы делят один синтетический origin-bucket, поэтому
они коллективно упираются в тот же per-origin бюджет; задавайте его
щедро (≥ 4 MiB) на таких сетях. `None` (default) полностью отключает cap
— применяется только глобальный лимит `max_store_bytes` (если выставлен).

Рекомендуемые профили:

| Deployment-профиль | `[dht] per_origin_max_bytes` | Обоснование |
|---|---|---|
| Leaf-клиенты | `None` | `max_store_entries = 0` уже подавляет хранение |
| Core-узлы | `Some(65_536)` | Worst-case fan-out одного signer'а (NameClaim + IdentityDocument + ~5 AppEndpointEntry) ≈ 12 KiB; 64 KiB оставляет 5× headroom |
| Dedicated DHT seeds | `Some(262_144)` | Более высокая per-origin толерантность — эти узлы несут authoritative-хранилище сети |
| Сети с `allow_unsigned_store = true` (явно повторно включён) | `Some(4_194_304)` | Щедрый bucket для unsigned shared-origin паттерна. Релевантно, только если вы opt'нулись обратно в legacy-флаг — теперь default `false`, и unsigned raw STORE'ы отвергаются напрочь |

Скрейп логов: попадания показываются как `[dht] STORE rejected: signer's
per-origin byte cap exceeded` — устойчивый burst от одного peer'а —
сильный индикатор попытки store-exhaustion (per-origin cap превращает
атаку из «заполнить store» в «заполнить свой собственный слайс»).

**2. `[dht] allow_unsigned_store`** — теперь default `false`
(secure-by-default). Сырые unsigned STORE'ы **отвергаются** на демоне с
`STORE rejected: unsigned authenticator + allow_unsigned_store=false`.
Это **не** полный блок legacy-публикации: self-authenticating записи
(NameClaim, IdentityDocument, InstanceRegistry, MlkemCert,
SignedBootstrap и magics AnnounceEndpoint / AnnounceAttachment) плюс
PBAN-баны несут свои собственные подписанные envelope'ы внутри blob'а
`value` и продолжают распространяться через валидированный путь
`store_with_origin` / gate-bypass диспетчера **независимо от этого
флага** — гейтятся только по-настоящему unsigned,
non-self-authenticating сырые STORE'ы.

Флаг существует как **явный opt-back-in** для операторов, которые всё
ещё гоняют truly unsigned legacy-STORE'ы. Когда выставлен обратно в
`true`, первый раз, когда узел принимает unsigned STORE через этот путь,
он логирует (once per process):

```
[dht] accepted unsigned STORE via allow_unsigned_store=true (legacy path) —
plan migration to signed STOREs; see docs/OPERATIONS.md → 'Этап 11e migration'
```

Последующие unsigned STORE'ы — тихие, чтобы избежать log spam'а.
Рекомендация — оставить флаг на его default'е `false`: inner-sig-путь
продолжает работать, если каждый STORE добавляет явный
`(ed25519_pubkey, ed25519_sig)` authenticator-кортеж, что стандартные
publish-хелперы делают автоматически.

Migration walkthrough:

```bash
# 1. Выставьте консервативный per_origin cap (64 KiB) — принимает всё
#    сегодня, но ограничивает blast radius если signer misbehaves.
echo '[dht]'                                       >> /etc/veil/node.toml
echo 'per_origin_max_bytes = 65536'                >> /etc/veil/node.toml

# 2. Reload и смотрите cleanup-tick output на deprecation-warn.
veil-cli -c /etc/veil/node.toml config reload
journalctl -u veil-node -f | grep 'allow_unsigned_store=true'

# 3. Свежий дефолтный config уже hard-fail'ит unsigned ingress
#    (allow_unsigned_store по умолчанию false). Этот шаг sed нужен
#    только для СТАРЫХ config'ов, которые явно выставляют `= true` — он
#    флипает их обратно на безопасный default после того, как вы
#    подтвердите, что unsigned STORE'ы не приземляются.
sed -i 's/allow_unsigned_store = true/allow_unsigned_store = false/' \
    /etc/veil/node.toml
veil-cli -c /etc/veil/node.toml config reload
```

Default для `allow_unsigned_store` **уже был флипнут на `false`**
(audit cycle-6, secure-by-default) — это больше не будущее событие
v1.0. Свежесгенерированный config отвергает unsigned raw STORE'ы из
коробки; deprecation-warn срабатывает только на config'ах, которые
явно повторно включили legacy-путь `= true`, давая тем операторам
сигнал к аудиту и миграции.

## Post-quantum signature algorithms (Этап 10)

Runtime поддерживает четыре алгоритма подписи (выбираются через
`[identity] algo = "<name>"` в `config.toml` или эквивалентными
CLI-флагами):

| Алгоритм | `algo = …` | wire byte | pk size | sig size | Use case |
|---|---|---|---|---|---|
| Ed25519 (default) | `ed25519` | 1 | 32 B | 64 B | Классический, быстрый — default для не-identity подписи |
| Falcon-512 (standalone) | `falcon512` | 2 | 897 B | ≤ 666 B | PQ-only, NIST PQC Level 1 |
| Ed25519 + Falcon-512 hybrid | `ed25519+falcon512` / `hybrid` | 3 | 929 B | ≤ 732 B | Классический + PQ Level 1 — рекомендуется для долгоживущих sovereign identities |
| Ed25519 + Falcon-1024 hybrid | `ed25519+falcon1024` / `hybrid1024` | 4 | 1825 B | ≤ 1528 B | Классический + PQ Level 5 — выше PQ-margin (~270-bit classical-equivalent vs ~103-bit для Falcon-512); используйте для identities, которые должны пережить CRQC-горизонт с бо́льшим запасом |

**Доступность Falcon-1024 hybrid** (Этап 10, слайс 1):
- ✅ **Доступно**: `veil-cli config sign` + `veil-crypto::sign_message`
  / `verify_message` / `generate_keypair` — sign-and-verify с
  `--algo ed25519+falcon1024`.
- ✅ **Доступно**: wire-format маппинги повсеместно
  (`veil-anonymity::directory` / `rendezvous`, `veil-bootstrap`,
  `veil-update::manifest`, `veil-identity::network_cert`,
  `veil-discovery::directory`, `veil-cfg::signed_config`,
  `veil-types::SignatureAlgorithm`). Декодер принимает wire byte
  `4` повсюду, энкодер эмитит его для нового варианта.
- ⏳ **Будущий слайс**: создание sovereign-identity
  (`veil-cli identity create --algo ed25519+falcon1024`). BIP-39
  master-seed derivation для layout'а Falcon-1024 hybrid (1825-байтный
  master_pubkey) требует своего отдельного freshness / rotation /
  recovery пути, прежде чем это можно будет безопасно поставить. До тех
  пор создание identity остаётся на `ed25519+falcon512` (рекомендуемый
  default).

**Выбор между Falcon-512 и Falcon-1024 hybrid**: каноническое
сопоставление NIST PQC Level 5 ≈ AES-256 ≈ Falcon-1024. Операторам,
гоняющим honest-and-correct identities на горизонты 50+ лет, следует
выбрать Falcon-1024 hybrid; всем остальным достаточно margin'а от
Falcon-512 hybrid (NIST PQC Level 1 ≈ AES-128), и они выигрывают от
в 4-5× меньших размеров подписи + ключей.

## TLS ECH (Этап 10 slice 2)

Encrypted Client Hello (ECH) — RFC 8744 + draft-ietf-tls-esni — шифрует поле
SNI в ClientHello, так что middlebox'ы не могут фингерпринтить целевой hostname
TLS-соединения.  Бо́льшая часть veil-трафика использует node-id-bound peer
transport (`tls://` с `set_verify(NONE)`), где SNI — это литерал node-id, а не
публичное DNS-имя, поэтому традиционный DNS-публикуемый ECH тут не применим.  Но
**путь публично-PKI HTTPS bootstrap** (`veil-bootstrap::https` тянет
подписанные seed-бандлы с CDN-URL) **говорит** обычным TLS к публичным DNS-именам,
и именно это соединение middlebox цензора стал бы фингерпринтить, чтобы построить
список целей.

### Фазы выкатки

| Slice | Статус | Что выкатывается |
|---|---|---|
| **2a** | ✅ выкачено 2026-05-28 | Флаг `GlobalConfig.tls_ech_grease` + audit-trail комментарий в точке интеграции (`veil-transport::tls::connect_pki_verified_https_stream`) + эта секция доков.  В slice 2a флаг — no-op, закладывает фундамент. |
| **2b + 2c** | ✅ выкачено 2026-05-28 | Бандлом.  Workspace мигрирован с `rustls-ring` на `rustls-aws-lc-rs` crypto-провайдер (4 quinn-фичи + 4 вызова `default_provider()` переключены с `crypto::ring` на `crypto::aws_lc_rs`).  Реальная разводка `EchMode::Grease(EchGreaseConfig::new(DH_KEM_X25519_HKDF_SHA256_AES_128, random_placeholder))` в точке вызова когда `TransportContext::tls_ech_grease == true`.  Дефолт флага флипнут на `true` (slice 2c), т.к. workspace-гейты прошли под aws_lc_rs без регрессий — операторы на TLS-1.2-only CDN могут override'нуть на `false`.  Пинит TLS 1.3 для публичного HTTPS-пути когда включено (ECH требует 1.3). |
| **3** | ✅ выкачено 2026-05-28 | Реальный ECH с `EchMode::Enable(EchConfig::new(...))`, управляемый lookup'ами DNS HTTPS RR (RFC 9460).  Новый хелпер `veil-transport::ech_dns::query_https_ech(host)` резолвит HTTPS-запись хоста и извлекает SvcParamKey `ech` (key 5).  `connect_pki_verified_https_stream` сначала пробует реальный ECH и откатывается на GREASE из slice 2c при любом DNS-сбое (NXDOMAIN, нет HTTPS-записи, нет `ech` SvcParamKey, битые байты, нет поддерживаемого HPKE-suite).  Модель soft-failure: DNS-ошибки логируются на DEBUG (`tls.ech.dns`), но никогда не пробрасываются как TLS-ошибки — GREASE-fallback доступен всегда.  Трейт `DnsResolver` расширен `resolve_https_ech` (default-impl возвращает `None`); `SystemDnsResolver` override'ит, чтобы использовать процесс-wide hickory `TokioResolver`, построенный лениво из системного конфига с таймаутом lookup'а 3 с. |

### Зачем нужен GREASE ECH

Без GREASE middlebox может отличить "ECH-capable" соединения (редкие сегодня) от
"non-ECH" соединений (основная масса веб-трафика).  Как только adoption ECH
переваливает порог, цензоры вынуждены в бинарный выбор:

- **Блокировать ECH-capable трафик**: видимый режим отказа — пользователи видят
  сломанные сайты и замечают цензуру.
- **Пропускать весь TLS**: ECH-real пользователи получают приватный SNI;
  ECH-GREASE пользователи получают cover-трафик.

GREASE — это половина «cover-трафика» в этом уравнении: он делает ECH-capable
соединения неотличимыми от non-ECH на TLS-уровне.  Даже до того как какой-либо
оператор опубликует реальный ECH-конфиг, флип GREASE на default-on на каждом
veil-клиенте добавляет эти соединения в общий пул cover-трафика.

### Конфиг оператора

```toml
[global]
# Дефолт slice 2c — `true`.  GREASE ECH на каждом публично-PKI HTTPS-fetch
# (bootstrap-бандл, signed-update манифест).  Override'ить на `false` только
# если вы застряли на TLS-1.2-only CDN.
tls_ech_grease = true
```

### Зачем пиннинг TLS 1.3

Билдер `with_ech` в rustls форсит только TLS 1.3 — ECH это расширение эпохи 1.3
и не существует в рукопожатии 1.2.  Современные публичные CDN (Cloudflare, Fastly,
AWS CloudFront, Google Cloud CDN) поддерживают 1.3 с ~2018, так что на практике
это не проблема.  Если очень старый CDN отказывает bootstrap-соединению после
флипа — override'ните `tls_ech_grease = false`, чтобы вернуть переговоры 1.2 + 1.3.

### Миграция зависимости (фон slice 2b)

Slice 2b переключил workspace с `rustls-ring` на `rustls-aws-lc-rs`.  rustls 0.23.x
поддерживает ECH только когда собран с crypto-провайдером `aws_lc_rs` (HPKE —
primitive внутреннего шифрования ECH — реализован только там).  Затронутая
поверхность: 4 quinn-фичи в Cargo.toml (veil-nat, veil-node-runtime,
veil-transport, veilcore) + 4 вызова `rustls::crypto::ring::default_provider()`
переключены на `rustls::crypto::aws_lc_rs::default_provider()` (3 в veil-nat,
1 в veil-transport).  Дельта размера бинаря: ~3 MB; дельта времени компиляции:
~20-30 с на железе класса M2.

### Публикация реального ECH-конфига (сторона оператора, slice 3)

Slice 3 читает `EchConfigList` из DNS HTTPS-записи целевого хоста.  Для оператора,
которому нужен реальный ECH для своего bootstrap-CDN, шаги такие:

1. **Сгенерировать HPKE-keypair** + EchConfig.  Используйте CLI [ech](https://crates.io/crates/ech)
   или [генератор ECH-конфигов Cloudflare](https://github.com/cloudflare/ech).
   Выберите HPKE-suite `DH_KEM_X25519_HKDF_SHA256_AES_128` (suite ID `0x0020,0x0001,0x0001`)
   — канонический дефолт, который rustls принимает под aws-lc-rs.

2. **Закодировать EchConfigList** в base64 (DNS-presentation форма значения
   `ech` SvcParamValue).

3. **Опубликовать HTTPS RR** под apex-доменом bootstrap-CDN:

   ```text
   bootstrap.veil.example.    300  IN  HTTPS  1 .  alpn="h2,http/1.1"  ech="AED+DQA8AAAgACAAAQABAAEAAABL..."
   ```

   * Priority `1` (предпочтительный).
   * Target `.` (отложить к A/AAAA-записям на том же имени).
   * SvcParamKey `alpn` отражает протоколы, которые отдаёт CDN.
   * SvcParamKey `ech` несёт base64-кодированный EchConfigList.

4. **Развернуть серверную поддержку ECH** на CDN.  Cloudflare, Fastly, AWS
   CloudFront, Google Cloud CDN экспонируют ручки ECH-конфига через свои
   control-plane'ы.

5. **Верифицировать**: на свежем veil-клиенте смотрите `journalctl -u veil-node`
   на INFO-строки `[tls.ech.dns]`, подтверждающие `real ECH selected
   host=bootstrap.veil.example`.  Если DEBUG-логи `tls.ech.dns` показывают
   "no supported HPKE suite available", опубликованный конфиг использовал suite
   вне [ALL_SUPPORTED_SUITES](https://docs.rs/rustls/0.23/rustls/crypto/aws_lc_rs/hpke/static.ALL_SUPPORTED_SUITES.html) aws-lc-rs — выберите поддерживаемый и переопубликуйте.

Пока операторы не опубликуют HTTPS-записи с SvcParamKey `ech`, slice 3 — тихий
no-op: каждый коннект пробует DNS-lookup, получает `None` (для большинства доменов
сегодня HTTPS-записи нет) и откатывается на GREASE из slice 2c.  Модель
soft-failure означает, что slice 3 выкатывается безопасно даже в сетях с нулём
реального ECH.

## Ротация TLS ClientHello fingerprint (tls-boring)

Исходящие `tls://` / `wss://` соединения могут предъявлять **браузерный TLS
ClientHello** (JA3/JA4) и **переключаться на другой при провале рукопожатия** —
так что цензор, заблокировавший один класс отпечатков (даже Chrome, приняв
сопутствующий ущерб), не рвёт связность.

> **Включено по умолчанию** (фича `tls-boring` в default-наборе бинарей
> `veil-cli`, `ogate`, `oproxy`, а также мобильного `veilclient-ffi`).
> Обычный `cargo build` / release даёт ротацию; бэкенд BoringSSL требует
> `cmake` + C/C++-тулчейн на сборке. **Отключить** для pure-Rust / кросс-сборок
> без cmake (роутеры, embedded):
>
> ```sh
> cargo build -p veil-cli --no-default-features --features rocksdb-cold
> ```
>
> Opt-out-сборка использует стек `rustls`, который не умеет менять свой
> ClientHello и **игнорирует** этот конфиг — отдаёт один фиксированный,
> опознаваемый-как-rustls отпечаток.

### Конфиг оператора

```toml
[transport.tls_fingerprint]
# "rotate" (default) | "pinned" | "random"
mode = "rotate"
# rotate: перебор по списку, пока рукопожатие не пройдёт; затем держимся
# за рабочий профиль (sticky), пока он снова не упадёт.
rotation = ["chrome", "firefox", "safari"]   # ещё: "ios", "android"
sticky = true
# pinned — предъявлять ровно этот профиль, без ротации:
# mode = "pinned"
# profile = "firefox"
```

| Режим | Поведение |
|---|---|
| `rotate` (default `[chrome, firefox, safari]`, `sticky=true`) | пробует каждый профиль по **свежему** соединению, пока TLS-рукопожатие не завершится; запоминает рабочий и держится за него до провала. Censorship-robust дефолт. |
| `pinned` | всегда предъявляет `profile`; без оверхеда ротации. |
| `random` | свежий рандомизированный (но валидный) ClientHello на каждое соединение. |

### Профили

| Токен | Отпечаток | Точность |
|---|---|---|
| `chrome` | Desktop Chrome | почти нативно (BoringSSL **и есть** TLS-стек Chrome) |
| `android` | Mobile Chrome | почти нативно |
| `firefox` | Desktop Firefox | приближение JA3-*класса*¹ |
| `safari` | Desktop Safari | приближение JA3-*класса*¹ |
| `ios` | Mobile Safari | приближение JA3-*класса*¹ |
| `random` | рандом на каждое соединение | валидная форма современного клиента |

¹ Нативные стеки Firefox/Safari/iOS (NSS / SecureTransport) иначе упорядочивают
TLS 1.3 cipher suites и часть расширений, а BoringSSL их фиксирует — поэтому
байт-в-байт **не** совпадает, но JA3-*класс* (порядок TLS 1.2 шифров,
supported-groups, signature algorithms, GREASE, перестановка расширений)
отличается. FFDHE-группы Firefox BoringSSL не отдаёт (только EC-кривые). Все
профили включают GREASE (как реальные браузеры).

### Режим ↔ тип DPI

| Поведение DPI | Лучший `mode` | Почему |
|---|---|---|
| **Blocklist** — режут известно-плохой JA3 | `random` (или `rotate`) | варьирующийся/случайный JA3 не в чёрном списке; нечего матчить. |
| **Allowlist** — режут всё, что не известный-хороший браузерный JA3 | `rotate` реальными браузерами | каждая попытка **и есть** разрешённый браузер; случайный JA3 зарежут как аномалию. |
| **Забанен один отпечаток** (напр. Chrome), сопутствующий ущерб принят | `rotate` | откатывается на следующий реальный браузер, который цензору дорого блокировать. |
| **Нет JA3-инспекции / только SNI** | `pinned` (или любой) | отпечаток неважен — см. ECH + `default_sni` ниже. |

Правило: под **allowlist**-DPI предпочитайте `rotate` через *реальные* браузеры
(случайный/редкий JA3 сам аномален и режется по default-deny); под
**blocklist**-DPI `random` максимизирует непредсказуемость.

### Слои: obfs4, ECH, SNI

Ротация отпечатка — один слой. Для defence-in-depth комбинируйте:

| Контроль | Что защищает | Конфиг |
|---|---|---|
| Ротация отпечатка | *каким клиентом* вы выглядите (JA3/JA4) | `[transport.tls_fingerprint]` |
| Транспорт **obfs4** | **вообще нет TLS ClientHello** — равномерно-случайный поток, нечего банить по JA3 | дайл пиров по `obfs4://` (+ `[transport] obfs4_psk_file`) |
| **ECH** | *какой хост* (реальный SNI скрыт) | `[global] tls_ech_grease = true` (default) |
| **SNI-маскировка** | SNI, предъявляемый при дайле пиров | `[transport] default_sni = "..."` |
| Ротация соединений | fingerprinting по *времени жизни* потока | `[transport.rotation]` |

Эскалация по мере закручивания цензуры:

1. `rotate` десктопными браузерами (default).
2. добавить мобильные: `rotation = ["chrome","firefox","safari","ios","android"]`.
3. убедиться, что ECH включён (default) + правдоподобный `default_sni`.
4. если заблокированы *все* браузерные JA3 (полный allowlist) → переводить
   пиров на `obfs4://` (нет отпечатка для бана) и/или `webtunnel` за
   обязательно-разрешённым CDN. Ротация JA3 не выигрывает против allowlist,
   исключающего все браузеры — там ответ «не предъявлять отпечаток вовсе», а не
   «предъявить другой».

### Границы

* **QUIC** (`quic://`) остаётся Chrome-формы — `quinn-btls` не даёт управлять
  шифрами/кривыми. Ротация покрывает только `tls://` и `wss://`.
* **Серверная сторона** (ServerHello вашего listener'а) не ротируется; это про
  исходящий ClientHello, который цензор инспектирует на *ваших* дайлах.
* **TLS через SOCKS** (`[transport] outbound_socks_fallback_proxy`) использует
  предпочтительный профиль политики **без** ротации — туннель уже установлен,
  переподключение под каждый отпечаток — забота прокси-слоя.
* Не-Chromium профили — приближения JA3-*класса*, не байт-в-байт (см. сноску в
  «Профилях»). Для байт-точной мимикрии не-Chromium браузера BoringSSL-варианта
  нет.

### Верификация

Ротированное рукопожатие логируется на DEBUG под target `tls.fingerprint`:

```text
[tls.fingerprint] fingerprint 'chrome' failed TLS handshake to peer:443, rotating: ...
```

Снимите исходящий ClientHello (`tcpdump` / Wireshark, фильтр
`tls.handshake.type == 1`) и посчитайте JA3, чтобы убедиться, что активный
профиль соответствует нужному классу браузера. Запинить один профиль для
контролируемого теста: `mode = "pinned"` + `profile = "firefox"`.

## Disaster recovery

State, переживающее рестарт (живёт рядом с `config.toml`):

| Файл | Содержимое | Критично |
|------|----------|----------|
| `bans.json` | Manual bans (персистентные) | Да — защищает от возвращающихся атакующих |
| `dht_values.json` | Локальные DHT shard values (sovereign identity records, name claims) | Да — sovereign-name resolution |
| `peers_discovered.json` | Peer'ы, выученные через PEX | Нет — re-discovered через PEX |
| `identity_document.bin` | Sovereign identity | **Да — бэкапьте** |
| `device_identity_sk.bin` | Per-device Ed25519 secret seed | **Да — бэкапьте** |
| `instance_id` | Local instance UUID + label | **Да** — привязан к identity_keys[] |
| `mlkem.key` | Per-instance ML-KEM-768 keypair | Авторегенерируется при отсутствии |
| `name_claims/*.bin` | Персистентные sovereign name claims | Да — re-publishable с диска |

### Crash + рестарт

```bash
# Hard kill
killall -9 veil-cli

# Рестарт подбирает bans.json, dht_values.json, identity_document.bin и т.д.
veil-cli -c /etc/veil/node.toml node run

# Проверьте, что state восстановлен
veil-cli -c /etc/veil/node.toml node show
veil-cli -c /etc/veil/node.toml peers banned
```

Логи на старте покажут `dht.values.persist.restored restored N/N` и
аналогичные; отсутствующие файлы тихо пропускаются (поведение fresh-node).

### Потеря identity — восстановление из BIP-39

Sovereign identities деривируются из 24-словной BIP-39 phrase,
эмитируемой `identity create`. Если хост уничтожен, но phrase сохранилась,
полное восстановление identity возможно:

```bash
# На fresh-хосте пере-создайте identity из сохранённой phrase
veil-cli identity import --phrase-file /path/to/phrase.txt --veil-dir /var/lib/veil/

# Проверьте, что identity_id совпадает с оригинальным
veil-cli identity show --veil-dir /var/lib/veil
```

Тот же `identity_id` воспроизводится; sovereign name claims и DHT-опубликованный
`IdentityDocument` остаются неизменными с точки зрения peer'ов.

### Ротация ML-KEM ключа

Если `mlkem.key` подозревается скомпрометированным:

```bash
# Остановите узел, удалите файл, перезапустите — auto-regenerated.
systemctl stop veil-node
rm /var/lib/veil/mlkem.key
systemctl start veil-node

# Re-publish ML-KEM cert через DHT (происходит автоматически на первом
# IdentityDocument re-publish; можно форсировать через debug-команду при необходимости)
```

Сессии, установленные до ротации, не затрагиваются (их session-ключи
не выводятся из `mlkem.key`); новые E2E-сообщения будут использовать свежий ключ.

### False-positive ban storm

Если misconfigured ban-pulse закинул всех в `bans.json`, и нужно зачистить
без потери identity / DHT state:

```bash
systemctl stop veil-node
mv /var/lib/veil/bans.json /var/lib/veil/bans.json.bak
systemctl start veil-node
# Селективно перебаньте конкретные node_id'ы при необходимости:
veil-cli peers ban <node_id_hex>
```

## Настройка значений по умолчанию

Значения по умолчанию рассчитаны на средний Core-узел (≥4 GB RAM,
≥100 Mbps). На стеснённом по ресурсам seed-узле (2 GB RAM, общая виртуалка)
или на укреплённом публичном узле несколько значений стоит переопределить.
Прочитайте этот раздел до развёртывания. На публичной инфраструктуре
неправильное значение по умолчанию — это разница между стабильным узлом и
бесконечным циклом перезапусков из-за нехватки памяти (OOM).

### RAM budget

Steady-state память доминирована тремя структурами:

| Структура | Per-unit стоимость | Дефолтный cap | Worst-case RAM |
|-----------|---------------|-------------|----------------|
| Session tx queues | `tx_queue_depth × avg_frame_size` ≈ 1024 × 1 KiB = 1 MiB | `max_concurrent = 65 536` | **~64 GiB** |
| DHT store | `key(32) + value(≤ MAX_DHT_VALUE_BYTES = 16384 ≈ 16 KiB)` ≈ 16 KiB | `max_store_entries = 25 000` (default; opt-up до ~250K для dedicated DHT seed'ов — дальше выносим на диск через RocksDB cold tier, `[dht] cold_store_path`) | **~400 MiB** на default, **~4 GiB** при 250K × 16 KiB |
| Route cache | `~200 bytes` на (dst, hop) пару | `~ K × 256` typical | <100 MiB |
| Mailbox WAL | disk-backed; RAM только для hot index | ограничен TTL | <500 MiB |

Худший случай патологичен: очередь каждой сессии полна, каждый DHT-слот
занят. Реалистичное установившееся состояние на публичном seed-узле с
~5 000 активных сессий и частично заполненной DHT — **~1–2 GB**. Но чтобы
прийти к нему от значений по умолчанию, придётся ограничить
`max_concurrent` и `max_store_entries`.

### Рекомендуемые переопределения по профилю развёртывания

#### Маленький seed (2 GB RAM, публичный IP, обслуживает клиентов)
```toml
[session]
max_concurrent = 4096            # 4K сессий × 1 MiB queue ≈ 4 GiB cap
max_per_ip = 256                 # допустить CGNAT-кластеры (mobile / residential)
max_per_subnet = 512             # /24 с большим количеством NAT'ed хостов

[dht]
# 25K теперь default. Оставляем явно для clarity.
# 25K × 16 KiB ≈ 400 MiB worst-case.
max_store_entries = 25_000

[capacity]
max_relay_sessions = 2048        # жёсткий cap на relay-нагрузку
max_inbound_bandwidth_kbps = 50_000   # 50 Mbit/s

[abuse]
pow_min_difficulty = 20          # отвергать low-PoW joiner'ов; ужесточить после инцидента
ban_max_secs = 86_400            # 24 ч escalated ban (default 1 ч мягковат)
```

#### Большой seed / infra-узел (≥8 GB RAM, dedicated HW)
```toml
[session]
max_concurrent = 65_536          # default — OK при таком RAM-бюджете
max_per_ip = 512

[dht]
# Opt-up с дефолта (25K) до 1M для dedicated DHT-инфры (1M × 16 KiB
# намного больше RAM — сочетать с дисковым cold-tier ниже).
max_store_entries = 1_000_000
# Дисковый cold-tier: значения, вытесненные из in-memory hot-тира,
# демотируются в RocksDB по этому пути вместо ограниченной in-memory карты —
# узел обслуживает **> 1M записей** без RAM-цены, а cold-записи переживают
# рестарт.  Нужен бинарь, собранный с фичей `rocksdb-cold` (включена по
# умолчанию для veil-cli).  Без фичи — или если открытие RocksDB упало —
# узел логирует и продолжает работать на in-memory cold-тире.
cold_store_path = "/var/lib/veil/dht-cold"

[capacity]
max_relay_sessions = 20_000
```

> **Hot-тир остаётся RAM-only.** `cold_store_path` персистит только *cold*-тир.
> Чтобы при рестарте восстанавливать и hot-записи, держите рядом
> `values_persist_path` (периодический JSON-снапшот) — они независимы и
> дополняют друг друга.

#### Leaf / end-user узел (ноутбук, phone gateway)
```toml
[session]
max_concurrent = 256             # клиенту много не надо
idle_timeout_secs = 180          # терпеть mobile sleep
keepalive_interval_secs = 60     # сохранить батарею

[dht]
participate = false              # leaf-узлы отказываются от DHT-хранения
max_store_entries = 0

[capacity]
max_relay_sessions = 0           # не релеить как клиент
```

### Per-field tradeoff таблица

| Поле | Default | Поднимать когда | Опускать когда |
|-------|---------|-----------|-----------|
| `session.max_concurrent` | 65 536 | Dedicated infra (>8 GB RAM) | Маленький seed / leaf (<4 GB) |
| `session.max_per_ip` | 32 | Обслуживаете mobile-NAT клиентов | Хардненинг против сканеров |
| `session.idle_timeout_secs` | 90 | Mobile / flaky-сети | Latency-sensitive / chat-only |
| `session.keepalive_interval_secs` | 30 | Battery-constrained клиенты (→120) | High-churn debug |
| `session.tx_queue_depth` | 1024 | Bulk-transfer воркллоады | High-concurrency RAM-lean |
| `dht.max_store_entries` | 1 000 000 | Dedicated DHT-инфра | **всегда для маленьких seed'ов** (→100k) |
| `dht.cold_store_path` | `None` (всё в памяти) | Dedicated DHT-инфра, обслуживающая > 1M записей (дисковый cold-tier, нужна фича `rocksdb-cold`) | Leaf / RAM-only узлы |
| `dht.k` | 20 | Никогда (влияет на wire) | Никогда |
| `dht.alpha` | 3 | Медленная сходимость lookup'а | High-cost link |
| `capacity.max_relay_sessions` | 0 (∞) | **выставляйте любое ≥ 0 для публичных узлов** | — |
| `capacity.max_inbound_bandwidth_kbps` | 100 000 | Enterprise-инфра | Residential / metered |
| `abuse.pow_min_difficulty` | 16 | Под атакой / ужесточение | Dev / LAN |
| `abuse.rate_limit_fps` | 500 | High-volume легитимные peer'ы | — |
| `abuse.ban_max_secs` | 3600 | Устойчивый abuse | Short-lived sandboxing |
| `routing.max_gossip_hops` | 2 | Никогда не поднимать > 3 (wire) | Маленький / fully-meshed mesh |

Флаги, которые **всегда** должны быть выставлены для публичной инфры:
- `capacity.max_relay_sessions > 0` — uncapped relay уязвим к DoS.
- `dht.max_store_entries` подогнан под RAM — default уронит 2 GB узел в OOM
  при worst-case.

## Развёртывание Core-узла

Все Core-узлы — равноправные участники с DHT (K=20), relay/forwarding'ом,
mailbox'ом и gateway-функциональностью.

### Требования
- **Железо**: ≥2 CPU cores, ≥2 GB RAM, ≥50 Mbps пропускной способности
- **PoW**: ≥24-битная сложность (mine'ить с `--difficulty 24`)
- **Uptime**: 99 %+ (systemd unit с `Restart=always`)

### Сниппет конфига
```toml
[identity]
role = "core"

[dht]
k = 20                    # размер Kademlia bucket'а (default)
alpha = 3                 # параллелизм lookup'а
shard_filtering = true    # принимать только local shards

[session]
max_concurrent = 512
tx_queue_depth = 4096

[gateway]
enabled = true            # default; установите false чтобы отключить gateway

[routing]
max_gossip_hops = 2
```

### Post-deploy верификация
```bash
# Role
veil-cli node show | grep -i role

# Routing table заполнена (после первого PEX walk, ≤2 мин)
veil-cli node dht routing | wc -l

# Снапшот метрик (включая DHT / route-cache gauge'и)
veil-cli node metrics
```
