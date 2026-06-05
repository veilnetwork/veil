# oproxy: прокси-мост для veil-сети

Система из двух бинарей, которая туннелирует локальный прокси-трафик
(SOCKS5 / HTTP / transparent) через veil-сессию к удалённому
exit-узлу, а затем — в обычный интернет.

```
[локальное приложение]
    │  SOCKS5  /  HTTP CONNECT  /  transparent (TPROXY)
    ▼
[oproxy-client]  ◀── подключается к локальному veil-daemon через IPC
    │
    │  veil-сессия (E2E-шифрование)
    │
    ▼
[veil-daemon на сервере]
    │
    │  bound endpoint → роутится к oproxy-server
    ▼
[oproxy-server]
    │ TCP CONNECT к host:port
    ▼
[настоящий интернет]
```

`oproxy-client` и `oproxy-server` оба подключаются к **локальному
veil-daemon** на своих хостах; прокси-трафик идёт через veil
между этими двумя демонами. English: [oproxy.md](../en/oproxy.md).

## Почему veil, а не обычный HTTPS-прокси

- **End-to-end veil-шифрование** — невозможно impersonate'нуть
  peer'а даже при компрометации CA; идентификаторы — sovereign
  ключевые пары.
- **Никаких открытых портов на сервере** — сервер не слушает на
  публичном IP для прокси-трафика; всё идёт через veil-туннель.
  Публичная поверхность атаки — это сам veil-daemon.
- **Custom app names** — несколько прокси-сервисов могут жить на
  одном daemon'е без коллизий портов (каждый получает уникальный
  `app_id`, derived из своего имени).
- **`node_id` allowlist на сервере** — отбрасывание неавторизованных
  peer'ов на app-уровне; никаких firewall-правил, сертификатов,
  ротации.

## Inbound-режимы

| Режим   | Use case                                    | Платформы |
|---------|---------------------------------------------|-----------|
| SOCKS5  | Browser SOCKS-прокси, `curl --socks5`       | Все (Linux / macOS / Windows / FreeBSD / Keenetic) |
| HTTP    | Browser HTTP/HTTPS-прокси (`HTTP_PROXY=...`)| Все |
| TProxy  | Transparent gateway (`iptables -j TPROXY`)  | Linux / Keenetic |

На одном клиенте можно запустить несколько inbound-listener'ов
одновременно.

---

## `oproxy-client`

Standalone-бинарь. Подключается к локальному veil-daemon, биндит
endpoint, слушает локально в одном или нескольких inbound-режимах и
туннелирует каждое подключение к настроенному upstream
`(server_node_id, server_app_name)`.

```bash
oproxy-client --config /etc/oproxy/client.toml
```

### Создание конфига с нуля

```bash
# 1. Сгенерировать шаблон (пишет в stdout — перенаправьте в файл).
sudo mkdir -p /etc/oproxy
sudo oproxy-client --gen-config | sudo tee /etc/oproxy/client.toml >/dev/null
sudo chmod 0640 /etc/oproxy/client.toml
sudo chown root:veil /etc/oproxy/client.toml

# 2. Отредактируйте — минимум: server_node_id, server_app_name, [[inbound]]-listener'ы.
sudo vim /etc/oproxy/client.toml

# 3. Запустите ОТ ПОЛЬЗОВАТЕЛЯ DAEMON'А (не root). Daemon отбрасывает
#    любое IPC-подключение, чей peer uid != его собственного (audit U9,
#    без исключения для root), поэтому root-клиент молча отбрасывается
#    на app-сокете.
sudo -u veil oproxy-client --config /etc/oproxy/client.toml
```

> **Запускайте от пользователя daemon'а, никогда не от root.** Veil-daemon
> проверяет совпадение peer-uid на уровне ядра (`SO_PEERCRED` /
> `getpeereid`) на своём IPC-сокете и отбрасывает любое подключение от
> другого uid — включая root. Запускайте `oproxy-client` от того же
> пользователя, под которым работает daemon (здесь `veil`). Для
> TProxy по-прежнему нужен `CAP_NET_ADMIN`; выдайте его этому
> пользователю (например, `setcap cap_net_admin+ep`), а не запускайте
> от root.

### Минимальный конфиг

```toml
socket_path     = "/var/lib/veil/app.sock"
server_node_id  = "00112233445566778899001122334455667788990011223344556677889900aa"
server_app_name = "my-proxy"

[[inbound]]
kind   = "socks5"
listen = "127.0.0.1:1080"
```

### Полный конфиг

```toml
socket_path     = "/var/lib/veil/app.sock"
server_node_id  = "<64-hex node_id хоста, где запущен oproxy-server>"
server_app_name = "my-proxy"

[[inbound]]
kind   = "socks5"
listen = "127.0.0.1:1080"

[[inbound]]
kind   = "http"
listen = "127.0.0.1:8080"

[[inbound]]
kind   = "tproxy"          # только Linux / Keenetic
listen = "0.0.0.0:12345"

# Опционально. Per-target маршрутизация — proxy / direct / block.
# По умолчанию: весь трафик через veil, без fallback (fail при недоступности veil).
[routing]
default  = "veil"   # veil | direct | block
fallback = "fail"      # глобальный default — может быть override'нут per-rule

[[routing.rules]]      # порядок имеет значение, первое совпадение выигрывает
host_suffix = ".internal"
action      = "direct"

[[routing.rules]]
cidr     = "10.0.0.0/8"
action   = "veil"
fallback = "direct"    # override: пробуем veil, при провале — direct

[[routing.rules]]
cidr     = "172.16.0.0/12"
action   = "veil"
fallback = "fail"      # override: пробуем veil, при провале — error

[[routing.rules]]
cidr   = "192.168.0.0/16"
action = "direct"      # никогда не через veil

# Опционально. Tokio-настройки — общая схема с veil-cli + ogate.
[runtime]
flavor               = "multi_thread"
worker_threads       = 4
max_blocking_threads = 64

# Опционально. Куда писать логи + уровень.
[logging]
level = "info"                       # off | error | warn | info | debug | trace
file  = "/var/log/oproxy-client.log" # опционально — по умолчанию stderr
```

---

## `oproxy-server`

Standalone-бинарь. Биндит veil app endpoint через IPC, принимает
входящие veil-стримы и форвардит каждый в запрошенный TCP-target.

```bash
oproxy-server --config /etc/oproxy/server.toml
```

### Создание конфига с нуля

```bash
# 1. Сгенерировать шаблон.
sudo mkdir -p /etc/oproxy
sudo oproxy-server --gen-config | sudo tee /etc/oproxy/server.toml >/dev/null
sudo chmod 0640 /etc/oproxy/server.toml
sudo chown root:veil /etc/oproxy/server.toml

# 2. Отредактируйте — минимум: app_name и либо список allowed_node_ids,
#    либо allow_all=true (явный opt-in на open-proxy).
sudo vim /etc/oproxy/server.toml

# 3. Запустите ОТ ПОЛЬЗОВАТЕЛЯ DAEMON'А (не root). Daemon отбрасывает
#    любое IPC-подключение, чей peer uid != его собственного (audit U9,
#    без исключения для root), поэтому root-сервер молча отбрасывается
#    на app-сокете.
sudo -u veil oproxy-server --config /etc/oproxy/server.toml
```

### Конфиг

```toml
socket_path = "/var/lib/veil/app.sock"
app_name    = "my-proxy"

# Опциональный allowlist по source node_id (hex). Пустой = open proxy.
allowed_node_ids = [
  "0011223344556677889900112233445566778899001122334455667788990011",
]

# При false (по умолчанию, рекомендуется) exit отказывает в outbound TCP к
# RFC1918 / loopback / multicast / link-local + cloud-metadata (169.254/16) /
# CGNAT (100.64/10) — включая их IPv4-mapped/-compatible IPv6-формы
# (`::ffff:a.b.c.d`, `::a.b.c.d`). Ставьте true только для намеренно
# LAN-обращённого exit.
allow_private = false

# Опционально. Общая схема runtime + logging.
[runtime]
flavor         = "multi_thread"
worker_threads = 2

[logging]
level = "info"
file  = "/var/log/oproxy-server.log"
```

`app_id` детерминированно вычисляется из `node_id` сервера +
`app_name`: клиенты с одинаковым `server_app_name` локально считают
те же байты и подключаются ровно к этому endpoint'у.

---

## Routing-режимы (client)

Секция `[routing]` управляет per-target dispatch'ем. Для каждого
`(host, port)`, который клиент получил через inbound-listener,
routing-движок проходит `rules` в порядке (первое совпадение
выигрывает) и применяет `action` совпавшего правила. Если ни одно
правило не совпало — применяется глобальный `default`.

### Actions

| Action    | Поведение |
|-----------|-----------|
| `veil` | Открыть veil-stream к `(server_node_id, server_app_name)` |
| `direct`  | Пропустить veil; TCP-connect напрямую с локального хоста |
| `block`   | Отказать с SOCKS5/HTTP error reply |

### Поля правила (все опциональные — пусто = wildcard; внутри правила AND)

| Поле | Совпадение |
|---|---|
| `host_suffix` | hostname заканчивается на эту строку (case-insensitive); `.internal` совпадёт с `db.internal` |
| `host_exact`  | hostname в точности равен этому (case-insensitive) |
| `cidr`        | host парсится как IPv4/IPv6 литерал И попадает в этот CIDR |
| `port_range`  | `"443"` (один порт) или `"1024-65535"` (inclusive range) |
| `action`      | (required) одно из `veil` / `direct` / `block` |
| `fallback`    | per-rule override; `direct` или `fail` |

**Примечание**: `cidr` совпадает только с IP-литералами — hostnames
DNS-резолвятся не на клиенте. Для hostname-based правил используйте
`host_suffix`.

### Семантика fallback

Применяется только когда `action = "veil"` и veil-путь
failed (сервер недоступен, timeout, denied, или rejected).

| `fallback` | При veil-failure |
|---|---|
| `fail` | Вернуть CONNECT failure inbound-клиенту (no recovery) |
| `direct` | Прозрачно TCP-connect напрямую, дальше bridge |

Возможность fallback'нуться существует только в фазах 1–3
veil-handshake'а (открыть stream / отправить connect header /
прочитать status reply). После начала фазы 4 (bridge) данные уже
текут в обе стороны — соединение «коммитнуто», любой failure
проходит к inbound-клиенту.

Per-rule `fallback` override'ит глобальный `[routing] fallback`.
Если опущен — берётся глобальное значение.

### Пример: RFC1918 split

```toml
[routing]
default  = "veil"   # всё остальное через veil
fallback = "fail"      # глобальный default — fail при недоступности veil

[[routing.rules]]
cidr     = "10.0.0.0/8"
action   = "veil"
fallback = "direct"    # 10/8 — пробуем veil, при провале → direct

[[routing.rules]]
cidr     = "172.16.0.0/12"
action   = "veil"
fallback = "fail"      # 172.16/12 — пробуем veil, fail-closed

[[routing.rules]]
cidr   = "192.168.0.0/16"
action = "direct"      # 192.168/16 — никогда не через veil
```

Итоговое поведение per-target:

| Target          | mode    | при veil-failure |
|-----------------|---------|---------------------|
| `10.x.x.x:*`    | veil | direct              |
| `172.16-31.x:*` | veil | fail                |
| `192.168.x.x:*` | direct  | n/a                 |
| всё остальное   | veil | fail (default)      |

---

## Конфигурация runtime + логирования

Общая схема с `veil-cli` и `ogate`. Обе секции опциональные;
при отсутствии применяются sensible defaults.

### `[runtime]`

```toml
[runtime]
flavor               = "multi_thread"   # | "current_thread"
worker_threads       = 4
max_blocking_threads = 64
thread_keep_alive_ms = 10000
thread_name          = "oproxy-client"
thread_stack_size    = 2097152
```

**Env-переменные** (применяются после загрузки конфига, выигрывают
над файлом):

| Env-переменная | Эффект |
|---|---|
| `OPROXY_RUNTIME` | `current_thread` или `multi_thread` |
| `OPROXY_WORKERS` | количество worker thread'ов |
| `OPROXY_MAX_BLOCKING_THREADS` | cap для blocking pool |

### `[logging]`

```toml
[logging]
level = "info"                  # off | error | warn | info | debug | trace
file  = "/var/log/oproxy.log"   # опционально — по умолчанию stderr
```

| Поле | По умолчанию | Описание |
|---|---|---|
| `level` | `info` | Минимальный уровень. `off` полностью пропускает инициализацию логгера (никаких логов — даже warning/error). |
| `file` | (stderr) | Опциональный путь к файлу. Логи **дописываются** (файл создаётся при отсутствии). Родительская директория должна существовать. |

`RUST_LOG` env-переменная override'ит `level`:

```bash
RUST_LOG=oproxy=debug oproxy-client --config client.toml
```

---

## Настройка TProxy на Linux / Keenetic

```bash
# Маркировка + routing трафика на listener:
iptables -t mangle -A PREROUTING -p tcp \
    --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 12345
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

oproxy-client --config client.toml
```

Listener принимает соединения с любой destination'ью и достаёт
оригинальный target через `SO_ORIGINAL_DST`. Нужно `CAP_NET_ADMIN`.

---

## Wire-протокол (oproxy-client ↔ oproxy-server)

После открытия veil-stream клиент отправляет connect header и
ждёт status reply:

```text
client → server:   [host_len u16 BE][host UTF-8][port u16 BE]
server → client:   [status u8]
```

| Status | Значение |
|---|---|
| `0x00` | Connected; продолжаем byte-pipe |
| `0x01` | Denied (node_id не в allowlist ИЛИ запрещённая destination) |
| `0x02` | Connect failed (DNS / TCP error) |
| `0x03` | Bad request (malformed header) |

При non-OK status сервер закрывает stream после ответа. Решение
клиента про `fallback` принимается на основе этого status (Denied /
Connect failed / Bad request — все считаются recoverable failures
в фазах 1–3).

---

## Связанный код

- [`crates/oproxy/src/config.rs`](../../crates/oproxy/src/config.rs) — TOML-схема
- [`crates/oproxy/src/routing.rs`](../../crates/oproxy/src/routing.rs) — per-target rule engine
- [`crates/oproxy/src/connector.rs`](../../crates/oproxy/src/connector.rs) — veil-side bridge + fallback
- [`crates/oproxy/src/inbound/`](../../crates/oproxy/src/inbound/) — SOCKS5 / HTTP / TProxy listeners
- [`crates/oproxy/src/logging.rs`](../../crates/oproxy/src/logging.rs) — logger init helper
- [`crates/oproxy/README.md`](../../crates/oproxy/README.md) — crate-level README

## Известные ограничения

- Нет UDP forwarding (только TCP).
- На клиенте нет DNS-резолва — hostname'ы форвардятся буквально
  на сервер, который делает свой DNS lookup. Поэтому `cidr`-rules
  не ловят hostname-таргеты (используйте `host_suffix`).
- FreeBSD TProxy сейчас застаблен (возвращает startup error при
  запуске); на FreeBSD используйте SOCKS5.
