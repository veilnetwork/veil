# Руководство пользователя

## Что такое Veil (OVL1)?

**Veil** — децентрализованная P2P-сеть с криптографической адресацией. Каждый узел сети идентифицируется 32-байтным `node_id = BLAKE3(public_key)` — адрес не зависит от IP, местоположения или транспорта. Приложения общаются через veil-адреса, а сеть сама находит пути доставки.

Что умеет OVL1:

- **Доставка сообщений** между узлами через произвольные промежуточные узлы (relay)
- **Mailbox** — хранение сообщений для офлайн-получателей на узлах-шлюзах
- **DHT** (распределённая хэш-таблица, Kademlia) — поиск узлов, публикация ресурсов
- **Имена** — человекочитаемые идентификаторы с Proof-of-Work привязкой к узлу
- **Стриминг** — двунаправленные потоки с управлением окном (аналог TCP поверх veil)
- **E2E-шифрование** — содержимое сообщений скрыто даже от relay-узлов (ML-KEM + ChaCha20-Poly1305)
- **Локальная сеть** — UDP mesh-broadcast для обнаружения соседей в одном сегменте

---

## Установка

Быстрый путь — готовые бинарники с проверкой sha256, без Rust-тулчейна:

**Linux / macOS:**

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.ps1 | iex
```

Ставит `veil-cli` в `~/.veil/bin` (`%USERPROFILE%\.veil\bin` на Windows). Добавьте `--all`, чтобы поставить также `ogate` и `oproxy` client/server. Компоненты, опции, серверная настройка и удаление — в **[Установке и первом узле](install.md)**.

> **Windows:** узел использует TCP-loopback для admin-протокола. Unix-удобства (SIGHUP-reload, Unix-домены сокетов) недоступны, но админ-CLI, основной veil-трафик и foreground-режим работают. Задайте `global.admin_socket = "tcp://127.0.0.1:0"`; узел выбирает порт у ядра и пишет `admin.port`/`admin.token` в `runtime_dir`, клиенты читают их при подключении.

### Сборка из исходников

Нужна только для платформ без готового бинарника (например, Intel macOS) или для разработки. Дефолтная сборка линкует BoringSSL (`tls-boring`) + RocksDB, поэтому нужен C/C++-тулчейн:

```bash
# Зависимости Debian/Ubuntu:
sudo apt-get install -y cmake golang-go nasm ninja-build build-essential

git clone https://github.com/veilnetwork/veil
cd veil
cargo build --release --features veil-bootstrap/production-seeds
# Бинарники: target/release/{veil-cli,ogate,oproxy-client,oproxy-server}
cp target/release/veil-cli ~/.local/bin/
```

Подробнее: [Установка → Сборка из исходников](install.md#сборка-из-исходников).

---

## Быстрый запуск

### 1. Создать конфигурацию

```bash
veil-cli config init
```

Команда создаёт `~/.config/veil/config.toml` (путь зависит от ОС) и **майнит PoW-nonce** для identity — это может занять несколько секунд. Nonce защищает от коллизий node_id.

Посмотреть, где лежит конфиг:

```bash
veil-cli config locate
```

Отобразить текущую конфигурацию:

```bash
veil-cli config show
```

### 2. Запустить узел

```bash
veil-cli node run
```

Узел запускается в фоне. Проверить состояние:

```bash
veil-cli node show
veil-cli node health
```

### 3. Посмотреть свой node_id

```bash
veil-cli node show
```

Пример вывода:

```
node_id:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
role:     leaf
listeners: 0
peers:    1 connected
```

### 4. Подключить к известному пиру

Добавить пир в конфигурацию:

```bash
# PUBLIC_KEY, NONCE и TRANSPORT — позиционные аргументы
veil-cli peers add \
  --algo ed25519 \
  BASE64_PUBKEY \
  BASE64_POW_NONCE \
  "tls://gateway.example.com:9443"
```

Перезапустить узел:

```bash
veil-cli node restart
```

### 5. Остановить узел

```bash
veil-cli node stop
```

---

## CLI — справочник команд

### `veil-cli config`

| Команда | Описание |
|---------|----------|
| `config init [PATH]` | Создать конфиг с новой identity и PoW-nonce |
| `config init --difficulty N` | Задать сложность PoW для генерируемой identity (дефолт `16`; используйте `24` или выше для продакшена / публичных узлов) |
| `config init --force` | Перезаписать существующий конфиг |
| `config show` | Вывести текущий конфиг (private_key скрыт) |
| `config validate` | Проверить конфиг на ошибки |
| `config validate --fix` | Попробовать исправить найденные ошибки |
| `config locate` | Показать путь к файлу конфига |
| `config get KEY` | Получить значение по ключу (например `identity.algo`) |
| `config set KEY VALUE` | Установить значение |

### `veil-cli key`

| Команда | Описание |
|---------|----------|
| `key gen` | Сгенерировать новую пару ключей (Ed25519 или Falcon512) |
| `key gen --algo falcon512` | Использовать постквантовый алгоритм |

### `veil-cli node`

| Команда | Описание |
|---------|----------|
| `node run` | Запустить узел |
| `-c PATH node run` | Запустить с нестандартным конфигом (глобальный флаг `-c`/`--config` идёт **перед** подкомандой) |
| `node stop` | Мягко остановить узел |
| `node restart` | Перезапустить (stop + run) |
| `node show` | Показать сводку (node_id, роль, сессии) |
| `node health` | Проверить живость event loop и количество сессий |

### `veil-cli listen`

| Команда | Описание |
|---------|----------|
| `listen add tcp://0.0.0.0:9000` | Добавить слушатель в конфиг (TRANSPORT — позиционный URI; есть опции `--advertise`/`--relay`) |
| `listen del LISTEN_ID` | Удалить слушатель (ID — позиционный) |
| `listen list` | Список активных слушателей |

### `veil-cli peers`

| Команда | Описание |
|---------|----------|
| `peers add [--algo ALGO] PUBLIC_KEY NONCE TRANSPORT [--alt-uri URI]` | Добавить пир (PUBLIC_KEY, NONCE, TRANSPORT — позиционные) |
| `peers del PEER_ID` | Удалить пир из конфига (ID — позиционный) |
| `peers list` | Список сконфигурированных пиров |

### `veil-cli sessions`

| Команда | Описание |
|---------|----------|
| `sessions list` | Активные OVL1-сессии (peer node_id, роль, RTT) |
| `sessions stats` | Агрегированная статистика сессий |

### `veil-cli debug`

| Команда | Описание |
|---------|----------|
| `debug ping NODE_ID [--count N] [--interval MS] [--timeout MS]` | Veil ping до node_id (64 hex-символа) |
| `debug trace TARGET [--max-hops N]` | Traceroute по veil-сети |
| `debug capture [--node-id HEX] [--family N] [--limit N]` | Захват фреймов для отладки |

`debug ping` / `debug trace` принимают только 64-символьный hex `NODE_ID`. Чтобы достучаться по `@name`, сначала разрешите его через `node resolve-name` (см. раздел «Имена» ниже).

---

## Имена (Name System)

OVL1 поддерживает человекочитаемые имена, привязанные к суверенной identity через PoW. Имена принадлежат бренчу `identity` (отдельной команды `name` не существует), а разрешение `@name` выполняется через `node resolve-name`.

### Заявить имя

```bash
veil-cli identity claim-name alice
```

Имя — позиционный аргумент; оно нормализуется к нижнему регистру ASCII (допустимы только символы `[a-z0-9#_-]`). Команда майнит PoW-nonce пропорционально редкости имени, подписывает `NameClaim` активным `identity_sk` и сохраняет его в `<veil_dir>/name_claims/<name>.bin`. Запущенный демон публикует заявку в DHT на ближайшем тике переопубликации (раз в 6 часов) или при перезапуске.

Опция `--veil-dir PATH` переопределяет каталог identity (по умолчанию `~/.config/veil` или `$VEIL_IDENTITY_DIR`).

### Найти имя

```bash
veil-cli node resolve-name @alice
```

Принимает как `alice`, так и `@alice`. Разрешает цепочку `NameClaim` → `IdentityDocument` с полной проверкой (сложность PoW, допуск по freshness-hour, проверка привязки имени к подписи активного подключа документа). Опция `--timeout-ms N` ограничивает суммарное время разрешения (по умолчанию 5000).

### DHT-ключ имени

Вычислить DHT-ключ, под которым публикуется `NameClaim` для заданного имени (без сетевого ввода-вывода):

```bash
veil-cli identity name-dht-key alice
```

---

## Использование приложением (IPC)

Если вы пишете приложение, которое должно работать через veil-сеть:

1. Включите IPC в конфиге:

```toml
[ipc]
enabled = true
socket_uri = "unix:///home/user/.veil/app.sock"
```

Ключ называется `socket_uri` и принимает URI (`unix:///абс/путь` на Linux/macOS или `tcp://127.0.0.1:0?runtime_dir=/абс/путь` на Windows), а не путь к файлу. Тильда `~` в URI не раскрывается — указывайте абсолютный путь. Если `socket_uri` не задан, на Unix демон использует `~/.veil/app.sock` по умолчанию.

2. Подключитесь к сокету и выполните handshake:

```python
# Пример на Python (упрощённо)
import socket, struct, json

sock = socket.socket(socket.AF_UNIX)
sock.connect("/home/user/.veil/app.sock")

def send_msg(s, obj):
    body = json.dumps(obj).encode()
    s.sendall(struct.pack(">I", len(body)) + body)

def recv_msg(s):
    n = struct.unpack(">I", s.recv(4))[0]
    return json.loads(s.recv(n))

send_msg(sock, {"command": "hello", "version": 1})
resp = recv_msg(sock)  # {"command": "hello_ok"}

send_msg(sock, {
    "command": "bind",
    "namespace": "myapp",
    "app_name": "main",
    "endpoint_id": 1
})
resp = recv_msg(sock)  # {"command": "bind_ok", "app_id": "...hex..."}
```

Подробнее об IPC-протоколе — в [Спецификации протокола](protocol-spec.md#ipc-протокол-localapp).

---

## Типичные сценарии использования

### Мессенджер peer-to-peer

1. Оба узла знают node_id друг друга (или имена `@alice`, `@bob`)
2. Приложение открывает `StreamOpen` → получает двунаправленный поток
3. Данные шифруются E2E (ML-KEM + ChaCha20-Poly1305)
4. При офлайн-получателе сообщение хранится в mailbox на gateway

### Публикация ресурса в DHT

Через IPC или admin API:
```bash
veil-cli node dht put HEX_KEY HEX_VALUE
```

### Мониторинг сети

```bash
veil-cli sessions list     # Активные соединения
veil-cli node routes       # Известные маршруты (route cache)
veil-cli node dht list     # Локальное хранилище DHT
veil-cli node metrics      # Счётчики фреймов, сессий, доставок
```
