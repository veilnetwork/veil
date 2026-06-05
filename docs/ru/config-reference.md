# Справочник конфигурации OVL1

Полное описание всех полей конфигурационного файла `config.toml`.

Конфиг читается при запуске командой `veil-cli node run`. Путь по умолчанию зависит от ОС (XDG на Linux, `AppData` на Windows); узнать его: `veil-cli config locate`.

---

## Формат файла

Файл в формате **TOML**. Большинство секций необязательны — если секция не указана, используются значения по умолчанию. Исключения: секция `[Identity]` и хотя бы один элемент `[[peers]]` или `[[listen]]` нужны для реальной работы узла.

```toml
# Пример минимального конфига (leaf-узел)
persist_enabled = true

[Identity]
algo       = "ed25519"
role       = "leaf"
public_key = "BASE64..."
private_key = "BASE64..."
nonce      = "AAAAAA=="

[[peers]]
peer_id    = "0x00000001"
algo       = "ed25519"
public_key = "BASE64..."
nonce      = "AAAAAA=="
transport  = "tls://gateway.example.com:9443"
```

---

## Верхний уровень

### `persist_enabled`

| Тип | По умолчанию |
|-----|-------------|
| `bool` | `true` |

Главный выключатель всей дисковой персистентности. Когда `false` — ни один `*_persist_path` не записывается и не читается при старте. Удобно для эфемерных узлов, CI, отладки.

---

## `[global]`

Настройки tokio runtime и логирования.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `runtime_flavor` | enum | `"multi_thread"` | Тип tokio runtime. Значения: `"multi_thread"`, `"current_thread"` |
| `worker_threads` | `u16` или отсутствует | не задано | Количество worker-потоков. Если не задано — `num_cpus`. Только для `multi_thread` |
| `max_blocking_threads` | `u16` или отсутствует | не задано | Пул blocking-потоков (для `spawn_blocking`). Нет — используется tokio-дефолт (512) |
| `thread_keep_alive_ms` | `u64` или отсутствует | не задано | Время жизни idle blocking-потока в мс |
| `thread_name` | `string` или отсутствует | не задано | Префикс имени worker-потоков (для `ps`, `top`) |
| `thread_stack_size` | `usize` или отсутствует | не задано | Размер стека worker-потоков в байтах |
| `admin_socket` | `string` или отсутствует | не задано | URI admin-бэкенда: `"unix:///abs/path/to/admin.sock"` (Linux/macOS) или `"tcp://127.0.0.1:0?runtime_dir=/abs/path"` (Windows или когда домен-сокеты недоступны). На TCP `admin.port` и `admin.token` пишутся в `runtime_dir` и читаются клиентами; запрет на non-loopback host включён в валидаторе (`::1`, `localhost` допустимы). |
| `logs` | enum | `"stderr"` | Куда писать логи. Значения: `"stderr"`, `"file"` |
| `log_file` | `string` или отсутствует | не задано | Путь к лог-файлу. Используется только когда `logs = "file"` |
| `log_level` | enum | `"info"` | Минимальный уровень логов. Значения: `"debug"`, `"info"`, `"warn"`, `"error"` |
| `log_format` | enum | `"text"` | Формат строк лога. Значения: `"text"` (человекочитаемый), `"json"` (NDJSON) |
| `admin_max_connections` | `usize` | `32` | Макс. одновременных подключений к admin-сокету |
| `require_signed_config` | `bool` | `false` | При `true` узел отказывается грузить неподписанный конфиг (Этап 11d) — см. подпись конфига в [OPERATIONS](OPERATIONS.md) |
| `tls_ech_grease` | `bool` | `true` | Слать TLS **ECH GREASE**, чтобы middlebox не отличал ECH-capable от не-ECH соединений. `false` только для TLS-1.2-only CDN |
| `bootstrap_dns_domain` | `string` или отсутствует | не задано | DNS-домен бутстрапа (TXT-запись как источник сидов — резервный слой) |
| `bootstrap_https_urls` | `[string]` | `[]` | HTTPS- (и `.onion`-) URL с **подписанным** seed-бандлом — последний резерв, когда clearnet-сиды заблокированы |
| `bootstrap_tor_socks_proxy` | `string` или отсутствует | не задано | SOCKS5-прокси (например `"socks5://127.0.0.1:9050"`) для загрузки `.onion`-`bootstrap_https_urls` через Tor |
| `trusted_bundle_issuer_pubkey` | `string` или отсутствует | не задано | Запиненный pubkey издателя, против которого верифицируются подписанные seed-бандлы |
| `legacy_allow_unsigned_bootstrap` | `bool` | `false` | Принимать неподписанные bootstrap-бандлы (legacy). Дефолт `false`; `.onion` всегда force-signed независимо от флага |
| `discovered_peers_cache_path` | `string` или отсутствует | не задано | Кэш пиров из прошлых запусков — резерв бутстрапа, если известные seed-IP лягут |

**Пример:**

```toml
[global]
runtime_flavor    = "multi_thread"
worker_threads    = 4
admin_socket      = "/var/run/veil/admin.sock"
logs              = "file"
log_file          = "/var/log/veil/node.log"
log_level         = "warn"
log_format        = "json"
```

---

## `[Identity]`

> Допускается также написание `[identity]` (строчными). Оба варианта эквивалентны.

Криптографическая идентичность узла. Единственная обязательная секция для работы.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `algo` | enum | `"ed25519"` | Алгоритм подписи. Значения: `"ed25519"`, `"falcon512"`, `"ed25519+falcon512"`, `"ed25519+falcon1024"` (последние два — постквантовые гибриды) |
| `role` | enum | `"leaf"` | Роль узла в сети. Значения: `"leaf"`, `"core"` |
| `public_key` | `string` | — | Публичный ключ, закодированный в base64. **Обязательно** |
| `private_key` | `string` | — | Приватный ключ, закодированный в base64. **Обязательно** |
| `nonce` | `string` | `"AAAAAA=="` (4 нулевых байта) | PoW-нонс для `node_id = BLAKE3(pubkey \|\| nonce)`. Генерируется при `config init` |
| `node_id` | `string` или отсутствует | вычисляется | Явный hex node_id (64 символа). Если не задан — вычисляется из `public_key` + `nonce` |
| `key_passphrase` | `string` или отсутствует | не задано | Пароль для расшифровки зашифрованного приватного ключа inline (не рекомендуется — лучше file/prompt-варианты) |
| `key_passphrase_file` | `string` или отсутствует | не задано | Путь к файлу с паролем ключа (держите mode `0600`) |
| `key_passphrase_prompt` | `bool` | `false` | При `true` спрашивать пароль ключа интерактивно при старте |
| `lazy_mining` | `bool` | `false` | Майнить PoW-нонс лениво в фоне вместо блокировки `config init` |
| `max_lazy_difficulty` | `u8` | `64` | Верхняя граница сложности, которую попробует ленивый майнер |

> Имена не являются ключами конфига — заявите имя командой `veil-cli identity claim-name <name>`; запущенный узел переопубликует его в DHT.

**Роли узла:**

| Роль | Описание |
|------|----------|
| `leaf` | Мобильный/слабый узел. Не участвует в DHT. Работает через core-ноды и mailbox |
| `core` | Полноправный участник сети. DHT (K=20), relay/forwarding, gateway (attachment records), mailbox. Рекомендуемая сложность PoW ≥ 24 (дефолт `--difficulty` = `16`; `MAX_POW_DIFFICULTY = 24` — жёсткий потолок) |

Legacy-значения `"relay"`, `"gateway"`, `"core_router"` удалены — парсер теперь
принимает только `"leaf"` или `"core"`.

**Пример:**

```toml
[Identity]
algo        = "ed25519"
role        = "core"
public_key  = "MCowBQYDK2VwAyEA..."
private_key = "MC4CAQAwBQYDK2Vw..."
nonce       = "AAAAAA=="
```

---

## `[[peers]]`

Массив постоянных пиров, с которыми узел поддерживает исходящее соединение. Каждая запись — одно соединение.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `peer_id` | `string` (hex u32) | — | Локальный идентификатор пира, например `"0x00000001"`. **Обязательно** |
| `public_key` | `string` | — | Публичный ключ пира (base64). **Обязательно** |
| `nonce` | `string` | — | PoW-нонс пира (base64). **Обязательно** |
| `transport` | `string` | — | URI транспорта для подключения (см. [Формат URI транспортов](#формат-uri-транспортов)). **Обязательно** |
| `algo` | enum | `"ed25519"` | Алгоритм подписи пира. Значения: `"ed25519"`, `"falcon512"` |
| `tls_cert` | `string` или отсутствует | не задано | PEM-сертификат для mTLS (клиентский) |
| `tls_key` | `string` или отсутствует | не задано | Приватный ключ для mTLS (клиентский) |
| `tls_ca_cert` | `string` или отсутствует | не задано | CA-сертификат для проверки сертификата пира |

**Пример:**

```toml
[[peers]]
peer_id    = "0x00000001"
algo       = "ed25519"
public_key = "MCowBQYDK2VwAyEA..."
nonce      = "AAAAAA=="
transport  = "tls://gateway.example.com:9443"

[[peers]]
peer_id    = "0x00000002"
algo       = "ed25519"
public_key = "MCowBQYDK2VwAyEB..."
nonce      = "AAAAAA=="
transport  = "quic://core.example.com:9444"
```

---

## Формат URI транспортов

Поле `transport` во всех секциях (`[[peers]]`, `[[listen]]`, `[[bootstrap_peers]]`) использует единый URI-формат. Реализация: `crates/veil-transport/src/uri.rs`.

### Поддерживаемые схемы

| Схема | Направление | Описание |
|-------|-------------|----------|
| `tcp://HOST:PORT` | исходящее / входящее | Прямое TCP-соединение без шифрования |
| `tls://HOST:PORT` | исходящее / входящее | TCP + TLS 1.3 |
| `quic://HOST:PORT` | исходящее / входящее | UDP + QUIC (встроенный TLS); поддерживает двунаправленные потоки, подпотоки и датаграммы |
| `ws://HOST:PORT/PATH` | исходящее / входящее | WebSocket через TCP; доступен как байтовый поток и поток сообщений |
| `wss://HOST:PORT/PATH` | исходящее / входящее | WebSocket через TLS; доступен как байтовый поток и поток сообщений |
| `socks://PROXY:PORT/TARGET:PORT` | только исходящее | TCP через SOCKS5-прокси |
| `sockstls://PROXY:PORT/TARGET:PORT` | только исходящее | TLS через SOCKS5-прокси |
| `unix:///path/to/socket` | только входящее | Unix Domain Socket (только IPC) |

**Bind-адреса для `[[listen]]`:** используйте `0.0.0.0` или `[::]` чтобы принимать соединения на всех интерфейсах; `127.0.0.1` или `unix://` — для локальных слушателей.  
**Для `[[peers]]` / `[[bootstrap_peers]]`:** DNS-имя или IP удалённого узла.  
**IPv6:** адреса оборачиваются в квадратные скобки: `tcp://[::1]:9000`, `tls://[2001:db8::1]:443`.

### Query-параметры для TLS-схем

Схемы `tls://`, `quic://`, `wss://`, `sockstls://` поддерживают query-параметры:

| Параметр | Повтор | Описание |
|----------|--------|----------|
| `sni=NAME` | один | Переопределить SNI (Server Name Indication) для TLS handshake. По умолчанию совпадает с `host`. У `sockstls://` по умолчанию — `target_host` |
| `alpn=PROTO` | много | Добавить ALPN-протокол. Можно указывать несколько раз |

**Примеры:**

```
# TLS с явным SNI (полезно при IP-подключении или reverse-proxy)
tls://10.0.0.1:9443?sni=node.example.com

# TLS с несколькими ALPN
tls://example.com:443?alpn=h2&alpn=http/1.1

# QUIC с ALPN
quic://example.com:9443?sni=example.com&alpn=h3

# WebSocket Secure с переопределённым SNI
wss://10.0.0.1:443/veil?sni=gateway.internal
```

### SOCKS5-прокси

Формат: схема `://proxy_host:proxy_port/target_host:target_port`

```
# TCP через SOCKS5-прокси
socks://127.0.0.1:1080/remote.example.com:9000

# TLS через SOCKS5-прокси (SNI автоматически = target_host)
sockstls://127.0.0.1:1080/remote.example.com:9443

# TLS через SOCKS5 с явным SNI и ALPN
sockstls://127.0.0.1:1080/10.0.0.5:9443?sni=remote.example.com&alpn=h2
```

### TLS-сертификаты

Параметры `tls_cert`, `tls_key`, `tls_ca_cert` в секциях `[[listen]]` / `[[peers]]` применяются только к схемам `tls://`, `quic://`, `wss://`. Для `tcp://`, `ws://`, `unix://` игнорируются.

| Параметр | В `[[listen]]` | В `[[peers]]` |
|----------|---------------|--------------|
| `tls_cert` | Сертификат сервера (PEM, leaf или fullchain) | Клиентский сертификат (mTLS) |
| `tls_key` | Приватный ключ сервера | Приватный ключ клиента |
| `tls_ca_cert` | CA для проверки клиентов (mTLS) | CA для проверки сертификата сервера |

> Не передавайте CA-сертификат в поле `tls_cert` для слушателя: rustls отклонит CA-сертификат, используемый как end-entity сертификат сервера.

### Отладка транспортов

Подкоманда `veil-cli debug transport` позволяет вручную тестировать подключения без запуска полноценного узла.

**Примеры подключения (клиент):**

```bash
veil-cli debug transport connect tcp://127.0.0.1:9001
veil-cli debug transport connect tls://example.com:443?sni=example.com&alpn=h2
veil-cli debug transport connect quic://example.com:443?alpn=h3
veil-cli debug transport connect unix:///tmp/veil.sock
veil-cli debug transport connect socks://127.0.0.1:1080/1.1.1.1:9001
veil-cli debug transport connect sockstls://127.0.0.1:1080/example.com:443?sni=example.com
veil-cli debug transport connect ws://127.0.0.1:8080/veil
veil-cli debug transport connect wss://example.com:443/veil?alpn=http/1.1
```

**Примеры слушателя (сервер):**

```bash
veil-cli debug transport listen tcp://0.0.0.0:9001
veil-cli debug transport listen unix:///tmp/veil.sock
veil-cli debug transport listen tls://0.0.0.0:9443?sni=localhost&alpn=h2
veil-cli debug transport listen quic://0.0.0.0:9444?alpn=h3
veil-cli debug transport listen ws://0.0.0.0:8080/veil
veil-cli debug transport listen wss://0.0.0.0:8443/veil?alpn=http/1.1
```

Для `listen` с TLS-схемами (`tls://`, `wss://`, `quic://`) автоматически генерируется временный самоподписанный сертификат. Для продакшн-тестирования передайте явные сертификаты:

```bash
# Слушатель с реальным сертификатом
veil-cli debug transport listen tls://0.0.0.0:9443 \
  --tls-cert ssl/server-fullchain.pem \
  --tls-key ssl/server.key

# Клиент с кастомным CA
veil-cli debug transport connect tls://127.0.0.1:9443 \
  --tls-ca-cert ssl/ca.pem

# Аналогично для WSS и QUIC
veil-cli debug transport listen wss://0.0.0.0:8443/veil \
  --tls-cert ssl/server-fullchain.pem --tls-key ssl/server.key
veil-cli debug transport connect wss://127.0.0.1:8443/veil \
  --tls-ca-cert ssl/ca.pem
```

Флаги `--tls-cert`, `--tls-key`, `--tls-ca-cert` работают одинаково для `tls://`, `wss://` и `quic://`.

---

## `[[listen]]`

Массив входящих слушателей. Каждый слушатель — один порт, на котором узел принимает соединения.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `id` | `string` (hex u32) | — | Локальный идентификатор слушателя, например `"0x00000001"`. **Обязательно** |
| `transport` | `string` | — | URI транспорта для привязки (см. [Формат URI транспортов](#формат-uri-транспортов)). **Обязательно** |
| `advertise` | `string` или отсутствует | не задано | Адрес, анонсируемый пирам вместо `transport`. Используется за reverse-proxy: привязка к `localhost:9443`, анонс `wss://nginx.example.com:443/veil` |
| `relay` | `string` или отсутствует | не задано | Hex node_id relay-узла, через который можно добраться до этого слушателя (для NAT). Включается в `RouteResponsePayload.relay_ids` |
| `tls_cert` | `string` или отсутствует | не задано | PEM-сертификат сервера (TLS/WSS) |
| `tls_key` | `string` или отсутствует | не задано | Приватный ключ сервера |
| `tls_ca_cert` | `string` или отсутствует | не задано | CA-сертификат для проверки клиентов (mTLS) |
| `visibility` | enum | `"public"` | Уровень видимости слушателя. `"public"` — анонсируется в PEX + DHT; `"trusted"` — не анонсируется (out-of-band invite); `"hidden"` — то же что trusted плюс enforce `allowlist_node_ids` при handshake |
| `psk_file` | `string` (путь) или отсутствует | не задано | Путь к файлу с PSK (32 байта, base64) для `obfs4-tcp://` слушателя. Переопределяет глобальный `[transport].obfs4_psk_file`. Позволяет разделить PSK по группам — публичный слушатель с deployment-wide PSK + семейный слушатель с приватным |
| `allowlist_node_ids` | `[string]` | `[]` | Список hex-encoded 32-байтовых node_id'ов, которым разрешено authenticate против этого слушателя. Обязательно для `visibility = "hidden"`; опциональное усиление для `"trusted"`. Пустой = без allowlist'а |
| `group_label` | `string` или отсутствует | не задано | Человекочитаемая метка группы (например `"family"`, `"snowflake"`). Не используется логикой daemon'а; отображается в логах + метриках |
| `ephemeral` | таблица или отсутствует | не задано | Конфигурация ротации случайного порта (anti-port-clustering). См. [`[listen.ephemeral]`](#listenephemeral) ниже |

**Пример:**

```toml
[[listen]]
id        = "0x00000001"
transport = "tls://0.0.0.0:9443"
tls_cert  = "/etc/veil/server.crt"
tls_key   = "/etc/veil/server.key"
advertise = "tls://node.example.com:9443"

[[listen]]
id        = "0x00000002"
transport = "ws://0.0.0.0:8080/veil"

# trusted-only obfs4 listener для семейного круга
[[listen]]
id          = "0x00000003"
transport   = "obfs4-tcp://0.0.0.0:5556"
visibility  = "trusted"
psk_file    = "/etc/veil/family.psk"
group_label = "family"
```

### `[listen.ephemeral]`

Периодическая ротация случайного порта для anti-port-clustering (snowflake-style).
Daemon перепривязывается на свежий порт из `range` каждые `rotation`; пиры узнают новый URI через подписанный `TransportMigrationNotify` broadcast.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `range` | `[u16, u16]` | — | Inclusive диапазон портов, например `[10000, 60000]`. Узкий диапазон полезен для mimicry под конкретный протокол (`[3306, 3306]` — MySQL-SSL). **Обязательно** |
| `rotation` | `string` (duration spec) | — | Интервал ротации: `"30s"`, `"5m"`, `"3h"`, `"7d"`. **Обязательно** |
| `bind_retries` | `u32` | `64` | Количество попыток bind при коллизии (`EADDRINUSE`). 0 = single-shot |
| `grace_period` | `string` (duration spec) | `"30m"` | Период после ротации, в течение которого старый слушатель остаётся жив для in-flight handshake'ов перед dropping |

**Ограничения:**

- Работает только для `obfs4-tcp://` слушателей (или другого транспорта, чья URI поддерживает `with_host_port`).
- Требует Ed25519 identity — wire-frame `TransportMigrationNotify` подписывается через ed25519-dalek; hybrid Falcon-512 + Ed25519 пока не поддерживается.
- При неудачном rebind на новом порту лога warn + старый слушатель остаётся в работе. Пиры, чьи кэши уже указывают на новый URI, fall back через DHT.

**Пример:**

```toml
[[listen]]
id        = "0x00000004"
transport = "obfs4-tcp://0.0.0.0:5556"   # стартовый порт (после первой ротации игнорируется)
psk_file  = "/etc/veil/ephemeral.psk"

[listen.ephemeral]
range         = [50000, 60000]
rotation      = "1h"
grace_period  = "30m"
bind_retries  = 64
```

**Логи и метрики:** при ротации daemon пишет structured-логи на info-уровне:

- `listen.rotation.spawned` — при старте, подтверждает что rotator-task поднялся
- `session.migration.notify.applied` — на стороне пира, при получении и применении broadcast'а
- `listen.rotation.swap_sent` — на стороне ротирующей ноды, после успешного rebind
- `listen.swap` — accept-loop переключился на новый слушатель
- `listen.rotation.rebind_failed` (warn) — если новый bind не удался; старый продолжает работать
- `listen.rotation.bind_failed` (warn) — если rotator не смог выбрать порт из range

### `[listen.on_demand]`

On-demand listener — slot привязывается **по запросу**, а не на старте.
По умолчанию `ss -tlnp` не показывает ни одного порта; порт открывается только после
успешного PoW handshake, обслуживает ограниченное число сессий (или TTL) и
автоматически закрывается.

**Требования:**

- `visibility = "stealth"` обязательно (иначе config-validation выкинет ошибку при старте)
- Идентификация ноды Ed25519 (hybrid Falcon-512 не поддерживается на этом слое)
- На ноду — **один stealth listener** (multi-stealth = TODO в Slice 6+)

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `range` | `[u16, u16]` | — | Inclusive диапазон портов для on-demand bind'а. **Обязательно** |
| `pow_difficulty` | `u32` | — | Требуемая PoW-сложность в leading-zero-bits BLAKE3. Production: 24 (~16M попыток ≈ 0.5 сек CPU). Минимум 8. **Обязательно** |
| `ttl` | `string` (duration) | — | TTL slot'а: `"5m"`, `"300s"`. После TTL accept-task выходит и слушатель закрывается, даже если ни одной сессии не пришло. **Обязательно** |
| `max_concurrent` | `usize` | `16` | Максимум одновременных on-demand slot'ов. Защищает FD-таблицу от PoW-funded бёрста |
| `rate_limit` | `string` (`"N/period"`) | `"3/h"` | Per-requester rate limit: `"3/h"` (3 grants в час на pubkey), `"1/m"`, `"10/30s"` |
| `max_accepts` | `usize` | `1` | Сколько сессий slot принимает до retire'а. 1 = one-shot rendezvous |
| `bind_retries` | `u32` | `64` | Попыток bind'а при EADDRINUSE |

**Пример:**

```toml
[[listen]]
id        = "0x00000005"
transport = "obfs4-tcp://example.com:0"   # port игнорируется для stealth
visibility = "stealth"
advertise = "obfs4-tcp://example.com"      # advertise_host для composing response URI

[listen.on_demand]
range          = [50000, 60000]
pow_difficulty = 24
ttl            = "5m"
max_concurrent = 16
rate_limit     = "3/h"
max_accepts    = 1
```

**Логи (info-уровень):**

- `rendezvous.controller.wired` — при старте, подтверждает что controller привязан к dispatcher
- `rendezvous.request.rejected reason=<кат>` — запрос отклонён (категории: decode, verify, not_our_target, rate_limited, concurrency_exhausted, bind_failed)
- `rendezvous.response.sent peer_id=<8 hex> new_port=<N>` — signed response отправлен инициатору
- `rendezvous.on_demand.listener.spawned listen_id=<id> local_addr=<addr> ttl_remaining=<sec> accepts_remaining=<N>` — on-demand listener поднят
- `rendezvous.on_demand.scanner_dropped` — banned-IP connection дропнут до handshake'а
- `rendezvous.on_demand.budget_exhausted` — все `max_accepts` слотов израсходованы, accept-task выходит
- `rendezvous.on_demand.listener.ttl_or_shutdown` — TTL истёк или runtime shutdown
- `rendezvous.on_demand.listener.exited` — final entry перед drop'ом listener'а

**Prometheus metrics (Slice 7):**

- `veil_rendezvous_requests_received_total` (counter) — всего запросов получено
- `veil_rendezvous_requests_granted_total` (counter) — выдано signed responses
- `veil_rendezvous_requests_rejected_decode_total` (counter)
- `veil_rendezvous_requests_rejected_verify_total` (counter)
- `veil_rendezvous_requests_rejected_not_our_target_total` (counter)
- `veil_rendezvous_requests_rejected_rate_limit_total` (counter)
- `veil_rendezvous_requests_rejected_concurrency_total` (counter)
- `veil_rendezvous_requests_rejected_bind_failed_total` (counter)
- `veil_rendezvous_slots_in_use` (gauge) — текущее количество активных on-demand listener'ов

Grant rate: `granted / received`. Высокий `rejected_verify_total` при низком `granted` = либо клиенты майнят слишком слабый PoW (поднять `pow_difficulty`), либо forge-attempts (rate-limit и anti-abuse работают). Высокий `rejected_concurrency_total` = `max_concurrent` слишком тесный для нормальной нагрузки.

**Что пока не реализовано (Slice 6+):**

- **Mediator routing**: на этом слое реализована только target-side обработка request frame'а, что предполагает что requester уже имеет OVL1-сессию с target'ом (что нонсенс для stealth listener'а у которого нет порта). Полная интеграция через PEX/DHT mediator-relay landит в Slice 6.
- **Интеграционные тесты** end-to-end: Slice 8.

До Slice 6 stealth listener работает в режиме "цепляется к dispatch path, но никто его не дотянется через mediator" — полезно для unit-testing'а контроллера и наблюдения через метрики при manual frame injection.

---

## `[[bootstrap_peers]]`

Bootstrap-пиры для начального заполнения DHT-таблицы маршрутизации. Используются только при старте: узел выполняет FIND_NODE(self), затем сессия закрывается (если пир не указан также в `[[peers]]`).

В отличие от `[[peers]]`, соединения с bootstrap-пирами **не поддерживаются** постоянно.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `transport` | `string` | — | URI транспорта (см. [Формат URI транспортов](#формат-uri-транспортов)). **Обязательно** |
| `public_key` | `string` | — | Публичный ключ bootstrap-узла (base64). **Обязательно** |
| `nonce` | `string` | `"AAAAAA=="` | PoW-нонс bootstrap-узла |
| `algo` | enum | `"ed25519"` | Алгоритм подписи. Значения: `"ed25519"`, `"falcon512"`, `"ed25519+falcon512"`, `"ed25519+falcon1024"` (последние два — постквантовые гибриды) |
| `tls_cert` | `string` или отсутствует | не задано | PEM-сертификат (если TLS-транспорт) |
| `tls_ca_cert` | `string` или отсутствует | не задано | CA-сертификат для проверки |

**Пример:**

```toml
[[bootstrap_peers]]
transport  = "tcp://bootstrap1.example.com:9000"
public_key = "MCowBQYDK2VwAyEA..."
nonce      = "AAAAAA=="

[[bootstrap_peers]]
transport  = "tcp://bootstrap2.example.com:9000"
public_key = "MCowBQYDK2VwAyEB..."
```

---

## `[metrics]`

Prometheus-экспортер метрик (HTTP). Секция необязательна; если не задана — метрики не экспортируются.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `listen` | `string` | — | Transport-URI для HTTP-сервера метрик — схема **обязательна**, например `"tcp://0.0.0.0:9090"` (голый `host:port` отвергается). Обязательно при наличии секции |
| `path` | `string` или отсутствует | `"/metrics"` | HTTP-путь для scrape |
| `auth_token` | `string` или отсутствует | не задано | Bearer-токен для scrape. Когда задан — запросы без него отвергаются |
| `allow_unauthenticated_remote_metrics` | `bool` | `false` | Разрешить не-loopback scrape без токена. Дефолт `false` — удалённый scrape требует `auth_token` |

**Пример:**

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

---

## `[transport]`

Настройки транспортного уровня и средств обхода цензуры (DPI-evasion). Все
ключи необязательны.

> **Бэкенд TLS.** Для бинарника `veil-cli` по умолчанию включён бэкенд
> BoringSSL (cargo-feature `tls-boring`, в составе `default = ["rocksdb-cold",
> "tls-boring"]`). Он формирует Chrome-подобный отпечаток JA3/JA4 в TLS
> ClientHello и поддерживает его ротацию. Бэкенд `rustls` доступен как fallback
> при сборке `--no-default-features` и не умеет подменять ClientHello —
> подсекция `[transport.tls_fingerprint]` на нём игнорируется.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `default_sni` | `string` или отсутствует | не задано | SNI-хостнейм по умолчанию в TLS ClientHello, когда исходящий URI не задаёт `?sni=...`, а цель не loopback. Например `"www.google.com"` — DPI на пути видит популярный домен вместо реального хостнейма узла. Не задано — использовать хост цели как SNI |
| `obfs4_psk_file` | `string` (путь) или отсутствует | не задано | Путь к файлу с obfs4 pre-shared key (32 байта, base64 в одну строку). При задании включает транспорт `obfs4-tcp://`: сервер проверяет входящие MAC, клиент добавляет MAC в исходящие рукопожатия. Единый сетевой PSK. Не задано — транспорт `obfs4-tcp` выключен |
| `webtunnel_secret_path` | `string` или отсутствует | не задано | Секретный путь webtunnel (например `/_t/random-32-chars`). Активирует tunnel-режим на серверной стороне транспорта `webtunnel-wss://` |
| `webtunnel_auth_token_file` | `string` (путь) или отсутствует | не задано | Файл auth-токена webtunnel (32 случайных байта в base64). Передаётся в заголовке `X-Veil-Auth` рядом с секретным путём |
| `webtunnel_decoy_dir` | `string` (путь) или отсутствует | не задано | Каталог decoy-контента webtunnel: статические файлы, отдаваемые пробам, не совпавшим с секретным путём/auth. Рекомендуется снимок нейтрального сайта. Не задано — минимальный встроенный HTML |
| `outbound_socks_fallback_proxy` | `string` или отсутствует | не задано | URL SOCKS-прокси, используемый как **fallback**, когда прямой дозвон повторно не удаётся (блокировка на уровне AS, перехват маршрута ISP). Формат `socks5://127.0.0.1:9050` (локальный Tor) или `socks5://proxy.example:1080`. Не задано — только прямые соединения |
| `bandwidth_mimicry_enabled` | `bool` | `false` | Имитация профиля полосы пропускания (P2 #7). Сейчас это **design landing-pad**: поле распознаётся, но слой шейпинга трафика ещё не подключён. Установка в `true` без `experimental_allow_noop_mimicry` приводит к ошибке валидации (fail-closed) |
| `bandwidth_mimicry_profile` | `string` или отсутствует | не задано | Имя профиля для `bandwidth_mimicry_enabled`: `"chrome-browsing"`, `"cdn-download"`, `"interactive-chat"`. Пока чисто landing-pad |
| `experimental_allow_noop_mimicry` | `bool` | `false` | Подтверждение, что `bandwidth_mimicry_enabled` сейчас no-op landing-pad, и согласие на запуск демона без реальной имитации. Обязательная пара к `bandwidth_mimicry_enabled = true` |
| `obfs4_accept_variants` | `[string]` | `[]` | **Kill-switch, серверная сторона**: список принимаемых вариантов obfs4 wire-format в порядке приоритета. Пусто (резолвится в `["v1"]`) сохраняет до-Phase-2 поведение. Значения: `"v1"`, `"v2"` |
| `obfs4_client_variant` | `string` или отсутствует | не задано | **Kill-switch, клиентская сторона**: вариант obfs4 wire-format для исходящих `obfs4-tcp://`. Не задано — резолвится в `v1`. Значения: `"v1"`, `"v2"`. Переключать на `"v2"` только после того, как у всех целевых серверов `obfs4_accept_variants` включает `v2` |

### `[transport.rotation]`

Политика ротации транспортного соединения. Принудительно периодически
пересоздаёт нижележащее TCP/TLS-соединение каждой сессии, чтобы DPI-классификация
по времени жизни потока (например «эта HTTPS-сессия живёт 6 часов — это VPN»)
потеряла сигнал. Каждая сессия при рукопожатии берёт случайное время жизни из
диапазона `[min_lifetime_secs, max_lifetime_secs]`. Секция **всегда
сериализуется** (как средство обхода цензуры оператор должен видеть её в своём
конфиге).

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `min_lifetime_secs` | `i64` | `1800` | Минимальное время жизни сессии в секундах (30 мин). `-1` — выключить весь механизм ротации. Положительные значения < 60 отвергаются валидацией |
| `max_lifetime_secs` | `i64` | `3600` | Максимальное время жизни сессии в секундах (1 час). `-1` — выключить ротацию. Должно быть `>= min_lifetime_secs`, когда оба положительны |

### `[transport.tls_fingerprint]`

Политика отпечатка TLS ClientHello для исходящих `tls://` / `wss://`
соединений. Действует **только на сборках с `tls-boring`** (бэкенд `rustls` не
умеет менять ClientHello и игнорирует эту секцию). Секция **всегда
сериализуется** — как и `[transport.rotation]`, это контрол обхода цензуры,
обнаруживаемый чтением конфига.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `mode` | enum | `"rotate"` | Режим: `"pinned"` (всегда `profile`), `"rotate"` (перебирать профили из `rotation` на свежих соединениях, пока одно не завершит рукопожатие), `"random"` (свежий рандомизированный ClientHello на каждое соединение). По умолчанию `"rotate"` — устойчив к блокировкам: когда один JA3 заблокирован, узел переключается на другой |
| `profile` | enum | `"chrome"` | Профиль для режима `"pinned"`. Токены профилей: `chrome`, `firefox`, `safari`, `ios`, `android`, `random` |
| `rotation` | `[string]` | `["chrome", "firefox", "safari"]` | Упорядоченный список профилей для перебора в режиме `"rotate"` |
| `sticky` | `bool` | `true` | В режиме `"rotate"` продолжать использовать последний профиль, завершивший рукопожатие, вместо повторного перебора с начала |

### `[transport.tls_client]`

Trust store для **исходящего** TLS узла (HTTPS-бутстрап, webtunnel). Опционально.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `connect_timeout_ms` | `u64` или отсутствует | не задано | Таймаут connect для исходящего TLS, мс |
| `use_system_roots` | `bool` | `false` | Включить CA-бандл Mozilla webpki-roots в client trust store. Дефолт `false` — veil доверяет только запиненным оператором CA через `trusted_ca_file`. Ставьте `true` для mesh-узлов, ходящих к публично-сертифицированным хостам |
| `trusted_ca_file` | `string` или отсутствует | не задано | PEM-файл запиненных оператором CA для доверия |

**Пример:**

```toml
[transport]
default_sni                    = "www.google.com"
obfs4_psk_file                 = "/etc/veil/obfs4.psk"
outbound_socks_fallback_proxy  = "socks5://127.0.0.1:9050"

[transport.rotation]
min_lifetime_secs = 1800
max_lifetime_secs = 3600

[transport.tls_fingerprint]
mode     = "rotate"
rotation = ["chrome", "firefox", "safari"]
sticky   = true
```

---

## `[mesh]`

Конфигурация локальной UDP mesh-сети (обнаружение соседей в одном сегменте). Секция необязательна.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `bind_addr` | `string` | — | UDP-адрес для realm-слушателя, например `"0.0.0.0:9100"`. **Обязательно** при наличии секции |
| `realm_id` | `string` | — | 32 hex-символа (16 байт) — идентификатор realm. **Обязательно** |
| `beacon_addr` | `string` | `"255.255.255.255:9100"` | Broadcast/multicast адрес для beacon-обнаружения. **Порт** здесь — единственный оставшийся traffic-shape сигнал маяка (размер и период уже скрыты при заданном `realm_psk`, C-03) — на враждебном LAN задайте нестандартный порт (одинаковый у всех участников realm) |
| `autodiscover_gateway` | `bool` | `true` | Автоматически подключаться к gateway-узлам, обнаруженным через mesh beacon |
| `autodiscover_max_concurrent` | `usize` | `3` | Максимум одновременных исходящих сессий к автообнаруженным gateway |
| `beacon_dedup_window_secs` | `u64` | `3` | Окно дедупликации beacon от одного источника в секундах. `0` — отключить дедупликацию |
| `autodiscover_persist_path` | `string` или отсутствует | не задано | Путь для сохранения таблицы `AutoDiscoveredPeers`. Восстанавливается при старте, чтобы знать ближайшие gateway до первого beacon |
| `require_signed_beacons` | `bool` | `true` | При `true` (по умолчанию, C-03) принимаются только криптографически подписанные mesh-beacon'ы; неподписанные отбрасываются, закрывая вектор on-link инъекции gateway / подмены соседних линков. Ставьте `false` только для legacy-совместимости с развёртываниями, ещё рассылающими неподписанные beacon'ы — включение «только подписанные» поверх живой неподписанной сети отрезает такие узлы, поэтому сперва раскатайте подписанные beacon'ы по всему флоту |
| `advertise_role_in_beacon` | `bool` | `false` | При `true` узел анонсирует свои role-флаги (`IS_GATEWAY` / `IS_RELAY` / `HAS_INTERNET`) в mesh-beacon — необходимо, чтобы пиры с `autodiscover_gateway` распознали узел как gateway. По умолчанию `false` (C-03): beacon несёт `role_flags = 0`, поэтому пассивный on-link наблюдатель не может выделить узел как gateway/relay (сигнал для таргетинга/цензуры). Стабильный `node_id` транслируется в любом случае |
| `realm_psk` | `string` или отсутствует | не задан | **Опциональная UDP-обфускация.** Base64-кодированный pre-shared key (≥ 16 байт после декодирования). При установке mesh-датаграммы типа **DATA** **и discovery-beacon'ы** заворачиваются в AEAD (`veil-udp-obfs`: ChaCha20-Poly1305, случайный nonce + случайный паддинг на каждую датаграмму) — пассивный DPI/LAN-наблюдатель видит только ротирующийся шифртекст, скрыт и mesh-фрейминг, **и стабильный `node_id` / role-флаги / dial-адрес в beacon'ах** (закрывает C-03; discovery тогда требует PSK, что ожидаемо для защищённого realm). Ключ общий для realm (HKDF от PSK и `realm_id`); **все участники realm должны иметь одинаковый PSK**, распространяемый out-of-band. Не задан (по умолчанию) → plaintext-mesh + plaintext-beacon'ы, поведение байт-в-байт неизменно. Заданный, но некорректный/слишком короткий PSK **отключает mesh**, а не откатывается молча на plaintext |

**Пример:**

```toml
[mesh]
bind_addr                  = "0.0.0.0:9100"
realm_id                   = "deadbeefcafebabedeadbeefcafebabe"
autodiscover_gateway       = true
autodiscover_max_concurrent = 5
autodiscover_persist_path  = "/var/lib/veil/autodiscover.bin"
# realm_psk                = "BASE64_PRESHARED_KEY"  # опционально: AEAD-обфускация DATA-датаграмм (≥16 байт, общий на realm)
```

---

## `[mailbox]`

Конфигурация mailbox — хранилища сообщений для офлайн-получателей.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Главный выключатель — узел держит mailbox только при явном включении |
| `quota_per_receiver_bytes` | `u64` | `0` (дефолт крейта) | Квота хранения на получателя, байт. `0` = встроенный дефолт |
| `quota_global_bytes` | `u64` | `0` (дефолт крейта) | Глобальная квота на relay, байт. `0` = встроенный дефолт |
| `quota_per_sender_bytes` | `u64` | `0` (дефолт крейта ≈ 10 MiB) | Квота на отправителя, байт. `0` = встроенный дефолт; `u64::MAX` фактически отключает учёт |
| `ttl_secs` | `u64` | `0` (дефолт крейта 7 дней) | TTL хранимого блоба, секунды. `0` = встроенный дефолт |
| `rate_limit_per_minute` | `u32` | `0` (дефолт крейта) | Лимит PUT на получателя в минуту. `0` = встроенный дефолт |
| `require_capability_token` | `bool` | `false` | При `true` PUT без токена отвергаются с `CapabilityRequired` |
| `[mailbox.push]` | таблица | отсутствует | Креды push-провайдера (FCM / APNs). Отсутствует ⇒ log-only диспетчер |

**Пример:**

```toml
[mailbox]
enabled                  = true
quota_per_receiver_bytes = 67108864   # 64 MiB
ttl_secs                 = 604800     # 7 дней
require_capability_token = true
```

### `[mailbox.push]`

Креды провайдера push-уведомлений (FCM / APNs). Когда пусто — демон использует log-only диспетчер (puts логируются, без вызова провайдера).

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `fcm_credentials_path` | `string` | `""` | Путь к service-account JSON Firebase Cloud Messaging |
| `apns_p8_path` | `string` | `""` | Путь к `.p8`-ключу подписи APNs |
| `apns_key_id` | `string` | `""` | Key ID APNs |
| `apns_team_id` | `string` | `""` | Team ID разработчика Apple |
| `apns_bundle_id` | `string` | `""` | Bundle ID приложения (topic APNs) |
| `apns_environment` | `string` | `"production"` | Окружение APNs: `"production"` или `"sandbox"` (пусто ⇒ production) |

---

## `[ipc]`

Конфигурация IPC-сервера для подключения локальных приложений через Unix-сокет.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Включить IPC-сервер |
| `socket_uri` | `string` или отсутствует | `~/.veil/app.sock` | IPC-endpoint. Принимает Unix-путь / `unix:///abs/path` или `tcp://127.0.0.1:0?runtime_dir=...` (TCP-loopback — путь для Windows) |
| `e2e_key_ttl_secs` | `u64` | `3600` | TTL кэша ML-KEM-768 ключей инкапсуляции пиров в секундах. После истечения — новый `RouteRequest/RouteResponse` для свежего ключа |
| `app_socket_dir` | `string` или отсутствует | не задано | Каталог, где узел открывает дополнительный per-app Unix-сокет `{app_socket_dir}/{hex(app_id)}.sock` для app-scoped IPC |

**Пример:**

```toml
[ipc]
enabled     = true
socket_uri = "/run/veil/app.sock"
e2e_key_ttl_secs = 1800
```

---

## `[priority_weights]`

Веса Weighted Round Robin (WRR) для 4 классов трафика в исходящем планировщике.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `realtime` | `u32` | `8` | Вес для REALTIME-трафика (голос, интерактив с жёстким RT) |
| `interactive` | `u32` | `4` | Вес для INTERACTIVE-трафика (обычный интерактив) |
| `bulk` | `u32` | `2` | Вес для BULK-трафика (передача файлов) |
| `background` | `u32` | `1` | Вес для BACKGROUND-трафика (фоновая синхронизация) |

Узел отправляет `realtime` фреймов класса REALTIME на каждые `background` фреймов BACKGROUND.

**Пример:**

```toml
[priority_weights]
realtime    = 16
interactive = 8
bulk        = 4
background  = 1
```

---

## `[proxy]`

Прокси-функциональность veil-узла.

### `[proxy.socks5]`

SOCKS5-прокси: узел принимает SOCKS5 CONNECT и туннелирует TCP через veil к exit-узлу.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Включить SOCKS5-слушатель |
| `listen` | `string` | `"127.0.0.1:1080"` | TCP-адрес для SOCKS5-слушателя |
| `exit_node_id` | `string` или отсутствует | не задано | Запинить exit по hex node_id — SOCKS5-трафик туннелируется на этот узел. Если не задан — exit выбирается динамически |

### `[proxy.exit]`

Exit proxy: узел принимает veil proxy-connect стримы и устанавливает исходящие TCP-соединения.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Включить exit proxy. При `true` этот узел форвардит соединения к внешним TCP-адресам |
| `allow_private` | `bool` | `false` | Разрешить exit-соединения к приватным/RFC1918 диапазонам (10/8, 172.16/12, 192.168/16, loopback). Дефолт `false` — заблокировано (SSRF-guard) |

**Пример:**

```toml
[proxy.socks5]
enabled = true
listen  = "127.0.0.1:1080"

[proxy.exit]
enabled = true
```

---

## `[tun]`

> **Перенесено.** TUN/TAP veil-VPN вынесен в отдельный бинарь **`ogate`** и
> теперь настраивается своим `ogate.toml` (per-network `peers[]` allowlist,
> `iface_name`, `mode`, `mtu`, …). В основном конфиге узла секции `[tun]` больше
> нет — см. **[ogate.md](ogate.md)**.

---

## `[session]`

Настройки сессионного уровня: keepalive, idle timeout, очереди.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `keepalive_interval_secs` | `u64` | `30` | Интервал отправки keepalive-фреймов в секундах. `0` — отключить |
| `idle_timeout_secs` | `u64` | `90` | Закрыть сессию, если за это время не получено ни одного фрейма. Должен быть > `keepalive_interval_secs` |
| `max_concurrent` | `usize` | `512` | Максимум одновременных OVL1-сессий |
| `max_per_ip` | `usize` | `32` | Максимум входящих сессий от одного IP-адреса |
| `max_pending_responses` | `usize` | `256` | Максимум ожидающих RPC-ответов на сессию. Превышение — дроп |
| `pending_response_ttl_ms` | `u64` | `30000` | TTL слота ожидающего ответа в мс. Устаревшие вытесняются |
| `tx_queue_depth` | `usize` | `4096` | Размер канала исходящих фреймов на сессию. Переполнение — дроп |
| `outbox_depth` | `usize` | `256` | Размер RPC outbox на сессию. При полном канале `send_request()` возвращает `None` |
| `max_frame_body_bytes` | `u32` | 1 МиБ | Максимальный размер тела фрейма. Фреймы больше отвергаются. Жёсткий потолок: 16 МиБ |
| `qos_weights` | `[u8; 4]` | `[8, 4, 2, 1]` | WRR-веса для классов `[RealTime, Interactive, Bulk, Background]` внутри сессии |
| `rt_queue_len` | `usize` | `64` | Глубина очереди REALTIME на сессию. Переполнение — дроп |
| `bg_queue_len` | `usize` | `256` | Глубина очереди BACKGROUND на сессию. Переполнение — дроп |
| `rekey_bytes_threshold` | `u64` | 128 ГиБ (`137_438_953_472`) | Инициировать rekey после этого объёма переданных байт на сессию |
| `rekey_time_threshold_secs` | `u64` | 32 дня (`2_764_800`) | Инициировать rekey после этого времени с момента последнего rekey или старта сессии |
| `max_per_subnet` | `usize` | `64` | Максимум входящих сессий из одной /24 (IPv4) или /48 (IPv6) подсети |
| `battery_threshold_low` | `u8` | `20` | Процент батареи, на/ниже которого применяется "low" keepalive-масштабирование |
| `battery_threshold_medium` | `u8` | `50` | Процент батареи, на/ниже которого применяется "medium" keepalive-масштабирование |
| `battery_keepalive_scale_low` | `f32` | `4.0` | Множитель keepalive-интервала при батарее ≤ `battery_threshold_low` |
| `battery_keepalive_scale_medium` | `f32` | `2.0` | Множитель keepalive-интервала при батарее ≤ `battery_threshold_medium` |
| `battery_sync_threshold` | `u8` | `15` | Процент батареи, ниже которого подавляется фоновая синхронизация |
| `allowed_peer_algos` | `[enum]` | `[]` | Allowlist алгоритмов подписи пиров, принимаемых на handshake (`"ed25519"`, `"falcon512"`, гибриды). Пусто = принимать все поддерживаемые |

**Пример:**

```toml
[session]
keepalive_interval_secs    = 15
idle_timeout_secs          = 60
max_concurrent             = 2048
max_per_ip                 = 64
tx_queue_depth             = 8192
max_frame_body_bytes       = 2097152        # 2 МиБ
rekey_bytes_threshold      = 68719476736    # 64 ГиБ — чаще ротировать ключи
rekey_time_threshold_secs  = 604800         # 7 дней
```

### `[session.padding]`

Шейпинг исходящего трафика (анти-фингерпринтинг). Опционально.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `mode` | enum | `"adaptive"` | Режим паддинга: `"adaptive"` (size-bucket паддинг), `"none"` (выкл), `"full"` (максимальный паддинг) |
| `jitter_ms` | `u32` | `0` | Макс. случайная задержка (мс), добавляемая к каждому исходящему кадру. `0` = без джиттера |
| `cover_interval_ms` | `u32` | `0` | Интервал (мс) между cover-кадрами (dummy) во время простоя сессии. `0` = без cover-трафика |

---

## `[hot_standby]`

Тёплый резервный транспорт: держать второй транспорт наготове, чтобы при отказе основного переключиться без обрыва сессии. Опционально.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Включить hot-standby переключение транспорта |
| `handoff_timeout_secs` | `u64` | `5` | Дедлайн на завершение handoff до его отмены |
| `max_swaps_per_minute` | `u32` | `4` | Лимит частоты свапов транспорта (анти-флап) |
| `auto_trigger_after_write_errors` | `u32` | `3` | Сколько подряд write-ошибок на основном авто-триггерят свап |

---

## `[gateway]`

Настройки gateway-функциональности (attachment records для leaf-узлов).
Доступна только для Core-нод.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Включить gateway (attachment records для leaf-узлов). Можно отключить на Core-ноде |
| `attachment_lease_ttl_secs` | `u64` | `300` | Время жизни attachment-lease без keepalive в секундах |
| `keepalive_interval_secs` | `u64` | `60` | Интервал отправки leaf→core keepalive в секундах. `0` — отключить (не рекомендуется в продакшене) |

**Пример:**

```toml
[gateway]
attachment_lease_ttl_secs = 600
keepalive_interval_secs   = 120
```

---

## `[nat]`

Конфигурация NAT traversal (hole punching + relay fallback).

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Включить NAT traversal. `false` — только если все пиры доступны напрямую |
| `punch_timeout_ms` | `u64` | `3000` | Максимальное время ожидания UDP hole-punch в мс. Затем — relay fallback |
| `stun_servers` | `[string]` | `[]` | Список внешних STUN-серверов (`"host:port"`, RFC 5389). Если пуст — адрес определяется через veil (core-узел отражает источник) |
| `relay_enabled` | `bool` | `true` | Разрешить relay fallback при неудаче hole-punch |

**Пример:**

```toml
[nat]
enabled          = true
punch_timeout_ms = 5000
relay_enabled    = true
stun_servers     = ["stun.l.google.com:19302", "stun1.l.google.com:19302"]
```

---

## `[pow]`

Настройки PoW-ограничителя скорости (rate limiter) для `PowChallenge`-фреймов.

Актуально только когда `abuse.pow_min_difficulty > 0`.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `challenge_rate` | `f64` | `1.0` | Устойчивая скорость выдачи PoW-вызовов на пира в секунду |
| `challenge_burst` | `f64` | `1.0` | Допустимый burst для PoW rate limiter на пира. Burst=1 достаточен для легитимного `RouteRequest`-потока |
| `challenge_window_secs` | `u64` | `300` | Скользящее окно PoW rate limiter state в секундах |

---

## `[connection]`

Настройки исходящих переподключений и gateway failover.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `reconnect_backoff_min_ms` | `u64` | `1000` | Минимальный интервал переподключения в мс |
| `reconnect_backoff_max_ms` | `u64` | `300000` | Максимальный интервал переподключения в мс (5 минут) |
| `prefer_internet_gateway` | `bool` | `true` | Предпочитать gateway с флагом `HAS_INTERNET` для маршрутизации к глобальным узлам. `false` — использовать ближайший gateway без учёта интернет-доступа |
| `gateway_failover_delay_secs` | `u64` | `5` | Минимальное время недоступности gateway (сек) перед переключением. Короткие разрывы игнорируются |
| `exit_diversification` | `bool` | `false` | Выбирать exit-gateway взвешенно-случайно из топ-K кандидатов вместо всегда лучшего — снижает статистический фингерпринтинг (один жирный поток к одному IP заметен) |
| `exit_diversification_top_k` | `u8` | `4` | Размер окна для `exit_diversification`: выбор из топ-K gateway по score |
| `reconnect_quiet_after_failures` | `u32` | `5` | Сколько подряд reconnect-неудач, после которых per-attempt логи понижаются WARN→DEBUG (продолжает ретраить; при восстановлении — `INFO peer.recovered`). `0` оставляет WARN навсегда |

**Пример:**

```toml
[connection]
reconnect_backoff_min_ms     = 500
reconnect_backoff_max_ms     = 60000
prefer_internet_gateway      = true
gateway_failover_delay_secs  = 10
```

---

## `[capacity]`

Ограничения нагрузки (load shedding) для relay-узлов. `0` = без ограничений.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `max_relay_sessions` | `usize` | `0` | Максимум одновременных relay-сессий. `0` — без ограничений |
| `max_total_sessions` | `usize` | `0` | Максимум всех сессий (relay + прямые). `0` — без ограничений |
| `tx_queue_high_watermark` | `f64` | `0.8` | Доля заполнения TX-очереди, при которой узел считается перегруженным (0.0–1.0) |
| `congestion_high` | `f64` | `0.8` | Порог congestion-score, выше которого узел отбрасывает новые relay-сессии |
| `congestion_low` | `f64` | `0.6` | Порог congestion-score, ниже которого узел возобновляет приём relay-сессий (гистерезис) |
| `max_inbound_bandwidth_kbps` | `i64` | `10000000` | Агрегатный лимит входящей полосы узла в kbps (дефолт 10 Гбит/с). `-1` — без лимита |
| `max_outbound_bandwidth_kbps` | `i64` | `10000000` | Агрегатный лимит исходящей полосы узла в kbps. `-1` — без лимита |

**Пример:**

```toml
[capacity]
max_relay_sessions      = 500
max_total_sessions      = 1000
tx_queue_high_watermark = 0.75
congestion_high         = 0.75
congestion_low          = 0.5
```

---

## `[abuse]`

Защита от злоупотреблений: rate limiting, mailbox-квоты, PoW, баны.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `rate_limit_fps` | `f64` | `200000.0` | Устойчивая скорость фреймов на пира (фреймов/сек) |
| `rate_limit_burst` | `f64` | `400000.0` | Burst-квота фреймов на пира |
| `pow_min_difficulty` | `u32` | `16` | Ведущие нулевые биты в PoW для `RouteRequest`/`PowChallenge` (≈65k хэшей, <1 мс). `0` отключает (только dev); жёсткий потолок `MAX_POW_DIFFICULTY = 24` |
| `ban_threshold` | `u32` | `5` | Число нарушений протокола до временного бана |
| `ban_initial_secs` | `u64` | `5` | Длительность первого бана (секунды) |
| `ban_step_secs` | `u64` | `5` | Добавка за каждый следующий бан — прогрессивно: N-й бан = `ban_initial_secs + N × ban_step_secs`, не выше `ban_max_secs` |
| `ban_max_secs` | `u64` | `3600` | Потолок прогрессивной длительности бана (секунды) |

**Пример (production-настройки):**

```toml
[abuse]
rate_limit_fps     = 200000.0
rate_limit_burst   = 400000.0
pow_min_difficulty = 16
ban_threshold      = 3
ban_initial_secs   = 30
ban_step_secs      = 30
ban_max_secs       = 7200
```

---

## `[routing]`

Тонкая настройка плоскости маршрутизации.

### Основные параметры

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `route_probe_interval_secs` | `u64` | `30` | Интервал отправки ROUTE_PROBE в секундах |
| `reannounce_interval_secs` | `u64` | `30` | Интервал переобъявления маршрутов в секундах |
| `route_cache_ttl_secs` | `u64` | `120` | TTL записей в кэше маршрутов |
| `route_request_backoff_ms` | `[u64; 3]` | `[500, 1000, 2000]` | Backoff для retry RouteRequest: [попытка0, попытка1, попытка2] мс |
| `partition_score_threshold` | `f64` | `0.2` | Минимальный `network_reachability_score` (0.0–1.0) до лога о разделе сети. `0.0` — отключить |
| `route_seen_capacity` | `usize` | `4096` | Размер кэша дедупликации маршрутов |
| `route_seen_window_secs` | `u64` | `120` | Окно дедупликации маршрутов в секундах |
| `max_gossip_hops` | `u8` | `2` | Максимальный TTL gossip-фреймов. Фреймы с большим hop count отбрасываются |

### ECMP и redundant send

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `ecmp_score_band` | `f64` | `0.20` | Максимальная относительная разница скоров для включения маршрута в ECMP-группу. `0.0` — отключить ECMP |
| `redundant_send` | `bool` | `false` | Отправлять критические фреймы одновременно по двум лучшим путям. Снижает p99-латентность ценой удвоения трафика |

### Адаптивные probe-интервалы

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `probe_min_interval_secs` | `u64` | `5` | Минимальный интервал ROUTE_PROBE при нестабильном пути |
| `probe_max_interval_secs` | `u64` | `120` | Максимальный интервал ROUTE_PROBE при стабильном пути |
| `probe_stability_threshold` | `f64` | `0.05` | Порог стабильности (`std_dev/mean` RTT). Ниже — путь стабилен, зонды отправляются реже |

### Epidemic broadcast

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `epidemic_fanout` | `usize` | `3` | Число случайных соседей для форварда `EpidemicBroadcast` |
| `epidemic_max_payload` | `usize` | `4096` | Максимальный размер payload для `EpidemicBroadcast` в байтах |

### Battery-aware routing

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `battery_penalty_low` | `f64` | `3.0` | Штрафной множитель при критически низком заряде (< `battery_threshold_low` %) |
| `battery_penalty_medium` | `f64` | `0.5` | Штрафной множитель при среднем заряде (< `battery_threshold_medium` %) |
| `battery_threshold_low` | `u8` | `20` | Порог (%) для применения `battery_penalty_low` |
| `battery_threshold_medium` | `u8` | `40` | Порог (%) для применения `battery_penalty_medium` |

### Distributed tracing

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `trace_sample_rate` | `f64` | `0.01` | Доля исходящих DELIVERY_FORWARD фреймов с инжекцией `trace_id` (0.0 = выкл, 1.0 = все) |
| `trace_buffer_size` | `usize` | `10000` | Размер кольцевого буфера trace-hop записей на узел |

### Персистентность

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `cache_persist_path` | `string` или отсутствует | не задано | Путь для снапшота кэша маршрутов. `None` — отключить |
| `cache_persist_interval_secs` | `u64` | `30` | Интервал записи снапшота маршрутного кэша |
| `cache_persist_max_age_secs` | `u64` | `3600` | Максимальный возраст снапшота при загрузке. Устаревшие файлы игнорируются |
| `rtt_persist_path` | `string` или отсутствует | не задано | Путь для снапшота RTT-таблицы |
| `rtt_persist_interval_secs` | `u64` | `60` | Интервал записи RTT-снапшота |
| `vivaldi_persist_path` | `string` или отсутствует | не задано | Путь для персистентности Vivaldi-координат |
| `gateway_persist_path` | `string` или отсутствует | не задано | Путь для персистентности списка gateway (ранжированный) |
| `peer_pubkeys_persist_path` | `string` или отсутствует | не задано | Путь для кэша публичных ключей известных пиров |
| `discovery_mode` | enum | `"public"` | Видимость, анонсируемая в handshake. Значения: `"public"`, `"contacts_only"` |
| `target_labels` | `[string]` | `[]` | Операторские метки, анонсируемые для label-based маршрутизации/выбора |
| `dht_fallback_timeout_ms` | `u64` | `10000` | Таймаут перед fallback на DHT-lookup, когда прямой route-discovery застопорился, мс |
| `dht_fallback_backpressure_threshold_pct` | `u8` | `75` | Процент заполнения очереди, выше которого DHT-fallback lookup'ы троттлятся |
| `dht_fallback_adaptive` | `bool` | `false` | Адаптивно подстраивать таймаут DHT-fallback по наблюдаемым задержкам |
| `dht_fallback_priority_mult` | `[u16; 2]` | `[50, 200]` | Множители приоритета `[floor, ceiling]` для DHT-fallback трафика |
| `multi_path_enabled` | `bool` | `false` | Слать по нескольким непересекающимся путям параллельно для устойчивости |
| `max_parallel_paths` | `u8` | `2` | Максимум непересекающихся путей при `multi_path_enabled` |
| `multi_path_min_priority` | `u8` | `1` (INTERACTIVE) | Multi-path только для трафика этого приоритета и выше |
| `relay_reputation_min_attempts` | `u32` | `10` | Минимум попыток через relay до включения downweighting по репутации |
| `relay_reputation_threshold` | `f64` | `0.5` | Success-rate, ниже которого relay понижается в весе |
| `relay_reputation_penalty` | `f64` | `2.0` | Множитель штрафа score для relay с низкой репутацией |
| `jitter_penalty_weight` | `f64` | `0.5` | Вес штрафа за RTT-джиттер в скоринге путей |
| `jitter_threshold_ms` | `u64` | `20` | Джиттер (мс), выше которого применяется штраф |
| `narrow_bandwidth_bulk_penalty` | `f64` | `2.0` | Множитель штрафа за маршрутизацию BULK-трафика по узкополосным линкам |

**Пример:**

```toml
[routing]
route_probe_interval_secs  = 20
reannounce_interval_secs   = 20
route_cache_ttl_secs       = 180
ecmp_score_band            = 0.15
redundant_send             = true
trace_sample_rate          = 0.05
cache_persist_path         = "/var/lib/veil/routes.bin"
rtt_persist_path           = "/var/lib/veil/rtt.bin"
vivaldi_persist_path       = "/var/lib/veil/vivaldi.bin"
gateway_persist_path       = "/var/lib/veil/gateways.bin"
peer_pubkeys_persist_path  = "/var/lib/veil/pubkeys.bin"
```

---

## `[dht]`

Настройки DHT (Kademlia) — фонового поиска узлов и хранения значений.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `republish_interval_secs` | `u64` | `1800` | Интервал переопубликации DHT-записей (30 минут) |
| `cleanup_interval_secs` | `u64` | `60` | Интервал очистки истёкших DHT-записей |
| `participate` | `bool` | `true` | Участвовать в DHT-хранилище (принимать STORE/DELETE). `false` — только маршрутизация (FIND_NODE/FIND_VALUE) |
| `k` | `u8` | `20` | Kademlia k-bucket size — контактов в ответе на FIND_NODE |
| `alpha` | `u8` | `3` | Kademlia α — параллельных запросов на раунд итеративного поиска |
| `max_rounds` | `u8` | `20` | Максимум раундов итеративного поиска до отказа |
| `find_node_timeout_ms` | `u64` | `2000` | Таймаут одного FIND_NODE/FIND_VALUE RPC в мс |
| `vivaldi_weight` | `f64` | `0.3` | Вес фактора топологии Vivaldi в рейтинге DHT-узлов. `0.0` — чистый XOR-порядок |
| `routing_persist_path` | `string` или отсутствует | не задано | Путь для персистентности DHT k-bucket таблицы маршрутизации |
| `values_persist_path` | `string` или отсутствует | не задано | Путь для персистентности хранимых DHT-значений (периодический JSON-снимок всего хранилища) |
| `cold_store_path` | `string` или отсутствует | не задано | Каталог для дискового **RocksDB cold tier** для вытесненных DHT-значений. Когда задан (и бинарник собран с feature `rocksdb-cold` — включён по умолчанию для `veil-cli`), значения, вытесненные из in-memory hot-tier, пишутся в этот RocksDB-стор на диске вместо ограниченной in-memory cold-карты. Снимает ограничение по числу записей с RAM на диск (выделенный DHT-узел обслуживает >1M записей), cold-записи переживают рестарт. Отличается от `values_persist_path` (периодический JSON-снимок): cold tier — живая, непрерывно обновляемая БД. Если feature отсутствует или RocksDB не открылся — игнорируется со строкой в логе при старте, узел откатывается на in-memory cold tier |
| `allow_unsigned_store` | `bool` | `false` | Принимать legacy **неподписанные** raw STORE. Дефолт `false` (отвергаются). Повторное включение — deploy-footgun, см. [OPERATIONS](OPERATIONS.md); при первом приёме срабатывает one-shot deprecation-warn |
| `max_store_entries` | `usize` | `25000` | Жёсткий лимит записей в DHT-сторе. Повышайте для выделенных DHT-сидов (например `250000`); чтобы выйти за RAM — пейджинг через RocksDB-tier `cold_store_path` |
| `max_store_bytes` | `u64` или отсутствует | не задано | Опциональный лимит DHT-стора по байтам (дополняет `max_store_entries`) |
| `per_origin_max_bytes` | `u64` или отсутствует | не задано | Байтовый лимит на одного подписанта (Этап 11e) — чтобы один origin не исчерпал стор |
| `shard_filtering` | `bool` | `false` | Opt-in: принимать STORE только если ключ попадает в шард этого узла. Дефолт `false`; станет default-on, когда сеть превысит ~1M узлов |

**Пример:**

```toml
[dht]
republish_interval_secs  = 3600
participate              = true
k                        = 20
alpha                    = 5
vivaldi_weight           = 0.5
routing_persist_path     = "/var/lib/veil/dht-routing.bin"
values_persist_path      = "/var/lib/veil/dht-values.bin"
cold_store_path          = "/var/lib/veil/dht-cold"
```

---

## `[pex]`

Peer Exchange — обнаружение пиров случайным блужданием. Опционально; разумные дефолты.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Включить PEX random-walk discovery |
| `max_peers` | `usize` | `32` | Макс. пиров, сохраняемых из PEX-discovery |
| `walk_parallelism` | `u8` | `3` | Параллельных walk-запросов за раунд |
| `max_response_peers` | `u8` | `16` | Макс. пиров в одном PEX-ответе |

---

## `[anycast]`

Политика разрешения anycast-сервисов.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `resolve_policy` | enum | `"signed_bound"` | Как принимаются anycast-записи. Значения: `"signed_bound"` (дефолт — подписанные + owner-bound), `"signed_only"` (отвергать неподписанные), `"best_effort"` (принимать любые — legacy, не рекомендуется) |

---

## `[mobile]`

Троттлинг с учётом батареи и фонового режима для мобильных / батарейных leaf-узлов. Опционально (профиль `mobile` заполняет его).

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `low_battery_threshold_pct` | `u8` или отсутствует | не задано | Процент батареи, на/ниже которого троттлятся probe-rate. Не задан — battery-awareness выключен; типично для мобильных `30` |
| `low_battery_multiplier` | `u32` | `4` | Множитель probe-интервала ниже порога батареи (4 = в 4 раза реже). Ограничен безопасным максимумом |
| `background_keepalive_multiplier` | `u32` | `1` | Множитель keepalive-интервала при выставленном runtime-флаге `background_mode` (композится с battery-scaling). `1` = выкл; профиль `mobile` ставит `60` (30 с → 30 мин) |
| `low_battery_throttle_maintenance` | `bool` | `false` | Троттлить и фоновые maintenance-задачи при низкой батарее. Рекомендуется для cellular/mobile |

---

## `[anonymity]`

Участие узла как onion-routing relay. Опционально. (Узел всегда использует анонимность для СВОИХ отправок; это управляет тем, несёт ли он чужие circuit'ы.)

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `relay_capable` | `bool` | `false` | Анонсировать capability `ANONYMITY_RELAY` и быть выбираемым как hop circuit'а. `false` = невидим для relay-directory lookup'ов |
| `advertised_bps` | `u32` | `0` | Самозаявленная (НЕПРОВЕРЯЕМАЯ) полоса relay в байт/сек для балансировки. Важно только при `relay_capable = true`. `0` = «не знаю / низший приоритет» |

---

## `[update]`

Самообновление через подписанные манифесты. Опционально — механизм включается только когда задан `expected_issuer_pk`.

| Ключ | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `manifest_urls` | `[string]` | `[]` | HTTPS-URL с подписанным манифестом оператора. Несколько разных провайдеров защищают от takedown одной точки |
| `expected_issuer_pk` | `string` или отсутствует | не задано | Hex-pubkey, которым должен быть подписан манифест. **Обязателен**, чтобы механизм обновления включился |
| `installed_version_path` | `string` или отсутствует | не задано | Файл с `release_unix` установленного бинарника. Нужен для apply-пути |
| `install_path` | `string` или отсутствует | не задано | Путь к самому бинарнику (atomic stage + rename target). Нужен для apply-пути |
| `check_interval_secs` | `u64` или отсутствует | не задано | Если задан — опрашивать `manifest_urls` каждые N секунд (жёсткий пол 60). Не задан — авто-опрос выключен |

---

## Полный пример конфигурации (gateway-узел)

```toml
persist_enabled = true

[Identity]
algo        = "ed25519"
role        = "core"
public_key  = "MCowBQYDK2VwAyEA..."
private_key = "MC4CAQAwBQYDK2Vw..."
nonce       = "AAAAAA=="
name        = "mynode"

[global]
log_level  = "info"
log_format = "json"
logs       = "file"
log_file   = "/var/log/veil/node.log"
admin_socket = "/var/run/veil/admin.sock"

[[listen]]
id        = "0x00000001"
transport = "tls://0.0.0.0:9443"
advertise = "tls://gateway.example.com:9443"
tls_cert  = "/etc/veil/server.crt"
tls_key   = "/etc/veil/server.key"

[[peers]]
peer_id    = "0x00000001"
algo       = "ed25519"
public_key = "MCowBQYDK2VwAyEB..."
nonce      = "AAAAAA=="
transport  = "tls://core1.example.com:9443"

[[bootstrap_peers]]
transport  = "tcp://bootstrap.example.com:9000"
public_key = "MCowBQYDK2VwAyEC..."
nonce      = "AAAAAA=="

[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"

[mesh]
bind_addr                 = "0.0.0.0:9100"
realm_id                  = "deadbeefcafebabedeadbeefcafebabe"
autodiscover_gateway      = false
autodiscover_persist_path = "/var/lib/veil/autodiscover.bin"

[mailbox]
enabled                  = true
quota_per_receiver_bytes = 67108864
ttl_secs                 = 604800
require_capability_token = true

[ipc]
enabled     = true
socket_uri = "/run/veil/app.sock"

[session]
keepalive_interval_secs = 15
idle_timeout_secs       = 60
max_concurrent          = 2048
max_per_ip              = 64

[abuse]
pow_min_difficulty     = 16
ban_threshold          = 3
ban_initial_secs       = 30
ban_step_secs          = 30
ban_max_secs           = 7200

[routing]
cache_persist_path        = "/var/lib/veil/routes.bin"
rtt_persist_path          = "/var/lib/veil/rtt.bin"
gateway_persist_path      = "/var/lib/veil/gateways.bin"
peer_pubkeys_persist_path = "/var/lib/veil/pubkeys.bin"

[dht]
participate          = true
routing_persist_path = "/var/lib/veil/dht-routing.bin"
values_persist_path  = "/var/lib/veil/dht-values.bin"
```
