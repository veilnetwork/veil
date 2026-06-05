# ogate: TUN-мост для veil-сети

`ogate` — пользовательское приложение, превращающее veil в виртуальную
приватную LAN. Каждый хост открывает TUN-устройство с настроенным
IPv4/IPv6 адресом; ogate пересылает IP-пакеты между TUN и veil-пирами
по таблице пиров, заданной в конфиге.

Два режима доступа:

* **`open`** — любой пир, знающий пару `(network, app)`, может слать
  пакеты внутрь.
* **`authorized`** — принимаются только пакеты от пиров, чей `node_id`
  явно в `peers[]`. Дополнительно `src_ip` пакета должен совпадать
  с виртуальным IP пира из таблицы (anti-spoof).

`ogate` — *приложение поверх* veil-демона (а не часть демона).
Один veil-демон может обслуживать несколько ogate-инстансов
одновременно — разные `(network, app)` пары дают разные IPC-биндинги.

## Соотношение с P-Net

Access mode у `ogate` независим от [P-Net](p-net.md) режима veil:

| Veil режим | ogate режим | Эффект |
|---|---|---|
| public | open | любой veil-пир заходит в LAN |
| public | authorized | LAN формируют только перечисленные `node_id` |
| private (P-Net) | open | любой P-Net-член заходит в LAN |
| private (P-Net) | authorized | двухуровневый allowlist (P-Net + ogate) |

Для любой LAN, где в veil могут оказаться недоверенные пиры, бери
`authorized`.

## Платформы

| Платформа | TUN backend | Настройка адреса |
|---|---|---|
| Linux | crate `tun` (`/dev/net/tun`, IFF_NO_PI) | crate ставит ipv4; ipv6 через `ip -6` |
| macOS | crate `tun` (utun) | crate ставит ipv4; ipv6 через `ifconfig` |
| Windows | crate `tun` (WinTun) | crate ставит ipv4; ipv6 через `netsh` |
| FreeBSD | прямой `/dev/tunN` + `TUNSIFHEAD` ioctl | `ifconfig inet ... up` |

На FreeBSD `iface_name` должен начинаться с `tun` (имя выделяет ядро).
Хочешь дружественное имя — после старта `ifconfig tunN name myiface`.

## Конфиг

`/etc/ogate/ogate.toml`:

```toml
network       = "homenet"
app           = "ogate"
mode          = "authorized"
socket_path   = "/var/lib/veil/app.sock"
iface_name    = "ogate0"
mtu           = 1280
local_addr_v4 = "10.99.0.1"
prefix_v4     = 24
local_addr_v6 = "fd00:1::1"
prefix_v6     = 64
endpoint_id   = 1

[[peers]]
node_id = "<64-hex node_id пира>"
addr_v4 = "10.99.0.2"
addr_v6 = "fd00:1::2"
name    = "host-b"

[[peers]]
node_id = "<ещё один 64-hex node_id>"
addr_v4 = "10.99.0.3"
name    = "host-c"
```

Обязательно: хотя бы один из `local_addr_v4` / `local_addr_v6`, плюс
соответствующий список пиров.

### Как назначаются подсети / IP

Статически — через этот конфиг. Оператор сам выбирает подсеть и IP
каждого пира. **Все пиры одной сети должны использовать одну и ту же
подсеть** и **зеркалить друг другу IP-таблицу**: `local_addr_v4` хоста A
должен совпадать с `peers[A].addr_v4` в конфиге хоста B и наоборот.
В режиме `authorized` несовпадение → пакет дропается как spoofed
source IP.

Для динамической / детерминированной выдачи IP (например, вывод из
`node_id`) — см. альтернативы в [`../../crates/ogate/README.md`](../../crates/ogate/README.md);
из коробки автоматического реестра нет.

## Вычисление app_id

Каждый ogate-биндинг — `app_id = BLAKE3(node_id || "ogate.<network>" || <app>)`.
Оба пира могут локально посчитать app_id друг друга — обмен peer-list'ом
с харвестом не нужен.

```bash
$ ogate app-id --network homenet --node-id $(cat host-a.nodeid)
namespace = ogate.homenet
name      = ogate
app_id    = 3c4e9f...
```

## Быстрый старт (два хоста)

### 1. Узнай `node_id` каждого хоста

```bash
sudo -u veil veil-cli --config /var/lib/veil/node.toml \
    node identity
```

### 2. `/etc/ogate/ogate.toml` на хосте A

```toml
network       = "homenet"
app           = "ogate"
mode          = "authorized"
socket_path   = "/var/lib/veil/app.sock"
iface_name    = "ogate0"
mtu           = 1280
local_addr_v4 = "10.99.0.1"
prefix_v4     = 24

[[peers]]
node_id = "<node_id хоста B в hex>"
addr_v4 = "10.99.0.2"
name    = "host-b"
```

### 3. Зеркало на хосте B

`local_addr_v4 = "10.99.0.2"`, и запись `peers` для хоста A с
`addr_v4 = "10.99.0.1"`.

### 4. Запуск (от пользователя демона, с CAP_NET_ADMIN)

ogate подключается к app-сокету демона через IPC. Peer-uid gate демона
(U9) **дропает любое IPC-подключение, у которого uid пира отличается от
uid демона — исключения для root нет** — поэтому ogate должен работать
от *того же* пользователя, что и veil-демон (например, `veil`),
а НЕ от root. Для открытия TUN-устройства нужен `CAP_NET_ADMIN`; выдай
его этому пользователю вместо запуска от root:

```bash
# Разово: разрешаем пользователю демона открывать TUN без root.
sudo setcap cap_net_admin+ep "$(command -v ogate)"

# Запуск от пользователя демона (совпадает с uid, под которым крутится демон):
sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

### 5. Пинг через виртуальный IP

```bash
ping 10.99.0.2   # с хоста A
```

## Hot reload (SIGHUP)

Отредактируй конфиг, потом просигналь демона:

```bash
sudo kill -HUP "$(pidof ogate)"
# Или через helper:
sudo ogate reload --pid "$(pidof ogate)"
# Или через systemd:
sudo systemctl reload ogate
```

Bridge перечитает конфиг и атомарно подменит routing-state.
Пакеты "в полёте" не теряются.

**Reloadable**: `mode`, `peers[]`.

**Не reloadable** (нужен restart): `network`, `app`, `endpoint_id`,
`iface_name`, `mtu`, `local_addr_v4`, `local_addr_v6`, `prefix_v4`,
`prefix_v6`, `socket_path`. Попытка поменять через SIGHUP логируется
warning'ом и игнорируется — текущее состояние сохраняется.

Ошибки reload'а (parse / validate / попытка нерезидентного поля)
логируются, прежнее состояние остаётся активным — окна с битым
состоянием не возникает.

## CLI

```
ogate up         --config <path>      Поднять TUN + bridge до SIGINT/SIGTERM.
ogate show       --config <path>      Распечатать конфиг + посчитать app_id
                                      (без открытия TUN / IPC).
ogate reload     --pid <pid>          Послать SIGHUP запущенному процессу.
ogate app-id     --network <net> --node-id <hex>
                                      Посчитать app_id одного пира
                                      (удобно при bootstrap'е конфигов).
ogate gen-config [-o <path>]          Вывести закомментированный шаблон конфига (TOML).
                                      Без -o ⇒ stdout (пайп в less / в твой редактор).
                                      С -o ⇒ пишет файл (отказывается перезаписывать
                                      существующий).
```

Флаги: `-v` — debug, `-vv` — trace. Или `RUST_LOG=ogate=debug` через env.

### Создание конфига с нуля

```bash
# 1. Сгенерировать шаблон (отказывается перезаписывать, если файл уже есть).
sudo -u veil ogate gen-config -o /etc/ogate/ogate.toml

# 2. Отредактировать — минимум: имя network, local_addr_v4, записи [[peers]].
#    Inline-комментарии `#` в шаблоне поясняют каждый параметр.
sudo vim /etc/ogate/ogate.toml

# 3. (Опционально) Проверить разобранный конфиг, не открывая ни одного устройства.
sudo -u veil ogate show --config /etc/ogate/ogate.toml

# 4. Поднять.
sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

## Конфигурация runtime + логирования

Оба настраиваются per-config, той же схемой что в `veil-cli` и `oproxy`.

### `[runtime]` — настройки tokio

```toml
[runtime]
flavor               = "multi_thread"   # | "current_thread"
worker_threads       = 4                # только для multi_thread
max_blocking_threads = 64
thread_keep_alive_ms = 10000
thread_name          = "ogate"
thread_stack_size    = 2097152
```

Все поля опциональные. `flavor` принимает legacy-alias
`runtime_flavor`. Нулевые значения `worker_threads` /
`max_blocking_threads` обрабатываются как «оставить unset» (factory
защищает от panic'а tokio при `0`).

**Env-переменные** (применяются после загрузки конфига — выигрывают
над файлом):

| Env-переменная | Эффект |
|---|---|
| `OGATE_RUNTIME` | `current_thread` или `multi_thread` |
| `OGATE_WORKERS` | количество worker thread'ов |
| `OGATE_MAX_BLOCKING_THREADS` | cap для blocking pool |

Backward-compat для systemd-юнитов, которые передают tuning через
env (до появления секции `[runtime]`).

### `[logging]` — настройки вывода

```toml
[logging]
level  = "info"                    # off | error | warn | info | debug | trace
format = "text"                    # text | json
file   = "/var/log/ogate.log"      # optional — по умолчанию stderr
```

| Поле | По умолчанию | Описание |
|---|---|---|
| `level` | `info` | Минимальный уровень. `off` полностью отключает логи (subscriber не регистрируется — нулевой overhead, полная тишина). |
| `format` | `text` | `text` = одна строка на событие; `json` = структурированный JSON (одна запись = одно событие). |
| `file` | (stderr) | Опциональный путь к файлу. Логи **дописываются** (файл создаётся при отсутствии). Родительская директория должна существовать. Writer non-blocking — параллельные log-вызовы не блокируются на disk I/O. |

**Приоритет** (выше → ниже):

1. `RUST_LOG` env-переменная (всегда выигрывает если задана)
2. CLI-флаги `-v` / `-vv` (когда > 0)
3. конфиг `[logging] level`
4. дефолт (`info`)

**Примеры:**

```toml
# Полностью тихий режим (никаких логов)
[logging]
level = "off"

# JSON-логи в файл для log-shipping (Promtail / Vector / Fluent Bit)
[logging]
level  = "info"
format = "json"
file   = "/var/log/ogate.json"

# Verbose в stderr (по умолчанию systemd → journald)
[logging]
level  = "debug"
format = "text"
```

```bash
# Override уровня через env при разовом запуске:
RUST_LOG="ogate=debug,veilclient=info" sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

## Ansible-раскатка

В репо лежат `ansible/deploy-ogate.yml` (раскатка) и
`ansible/remove-{chat,chaos-ban}.yml` (снос старых тестовых нагрузок).
Rolling deploy (`serial: 1`), config на каждый хост шаблонизируется
из `manifest.json` + карты `host_to_ogate_addr` внутри плейбука.

```bash
# Раскатить:
ansible-playbook -i inventory.yml deploy-ogate.yml

# Обновить peer-таблицу без рестарта (после правки /etc/ogate/ogate.toml):
ansible all -i inventory.yml -m systemd \
    -a "name=ogate state=reloaded" --become

# Остановить везде:
ansible all -i inventory.yml -m systemd \
    -a "name=ogate state=stopped enabled=no" --become
```

Текущий testnet работает в `mode=authorized` поверх `192.168.0.0/16`:
* bootstrap-ноды: `192.168.0.1`–`.3`
* leaf-ноды: `192.168.0.11`–`.15`

## Заметки по архитектуре

* **Транспорт**: каждый IP-пакет с TUN заворачивается в `AppIpcSend`-
  сообщение через IPC-хэндл и далее идёт через демон как обычная
  veil-датаграмма. ogate НЕ использует устаревшее daemon-side
  `Tunnel`-семейство фреймов.
* **Стоимость пакета**: TUN read → unix socket write → demon E2E
  encrypt → wire → demon decrypt → unix socket → TUN write. Unix-
  socket IPC на Linux держит 100k+ маленьких сообщений/сек, так что
  bottleneck скорее в крипто демона или в сети, чем в самом ogate.
* **Авторизация**: на app-layer на ingress'е. В режиме `authorized`
  для каждого пришедшего пакета проверяется и членство `src_node_id`
  в peer-таблице, и совпадение `src_ip` с `peers[src_node_id].addr_*`.
* **Anti-spoof**: в `authorized` режиме пир не может слать пакеты от
  имени не-своего виртуального IP.

## Ограничения / открытые вопросы

* Нет управления маршрутами помимо неявного subnet-route'а —
  per-host маршруты через пиров надо добавлять руками через
  `ip route` / `route add`.
* Нет NAT / форвардинга — `ogate` это endpoint, не gateway. Если
  нужна gateway-семантика: `net.ipv4.ip_forward=1` (Linux) + NAT-
  правила добавлять самому.
* Производительность не замерена. Перед оптимизацией — `iperf3`.

## Связанный код

* [`crates/ogate/src/config.rs`](../../crates/ogate/src/config.rs)
* [`crates/ogate/src/app_id.rs`](../../crates/ogate/src/app_id.rs)
* [`crates/ogate/src/routing.rs`](../../crates/ogate/src/routing.rs)
* [`crates/ogate/src/tun/`](../../crates/ogate/src/tun/)
* [`crates/ogate/src/bridge.rs`](../../crates/ogate/src/bridge.rs)
* [`ansible/deploy-ogate.yml`](../../ansible/deploy-ogate.yml)
