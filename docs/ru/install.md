# Установка и первый узел

Это руководство проведёт вас от одной команды `curl` до работающего узла
veil — и для новичка, который впервые видит проект, и для оператора,
поднимающего парк серверов.

Установщик скачивает **готовые бинарники с проверкой sha256** из GitHub
Releases. Rust-тулчейн не нужен (он требуется только при
[сборке из исходников](#сборка-из-исходников)).

---

## Коротко — однострочники

**Linux / macOS:**

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.ps1 | iex
```

Затем запустите узел:

```sh
veil-cli config init      # свежая identity + конфиг
veil-cli node run         # запуск в фоне
veil-cli node show        # node id, аптайм, пиры
```

Готово. Ниже — как доставить gateway/proxy, поднять публичный сервер и настроить установку.

---

## Что устанавливается

По умолчанию ставится только **`veil-cli`** (узел + самообновление), в
пользовательский каталог без `sudo`:

| Платформа | Путь |
|-----------|------|
| Linux / macOS | `~/.veil/bin` (добавляется в `PATH` через `~/.veil/env`) |
| Windows | `%USERPROFILE%\.veil\bin` (добавляется в пользовательский `PATH`) |

Можно поставить любой набор из четырёх бинарников:

| Бинарник | Роль | Сторона |
|----------|------|---------|
| `veil-cli` | Узел: вход в сеть, маршрутизация, DHT, identity, самообновление | клиент **или** сервер |
| `ogate` | Мост IP-поверх-veil (виртуальный LAN) | сервер / шлюз |
| `oproxy-client` | Локальный SOCKS5 / HTTP / TProxy → veil | клиент |
| `oproxy-server` | Выходной / proxy-сервер veil | сервер |

Поставить больше, чем узел:

```sh
# всё (узел + ogate + oproxy client & server)
curl -sSf https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.sh | sh -s -- --all

# конкретный набор
... | sh -s -- --components ogate,oproxy-server
```

На Windows:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.ps1))) -All
```

---

## Запуск узла

### Клиент / лист (по умолчанию)

Лист подключается *наружу*; публичный адрес не нужен, работает за NAT.

```sh
veil-cli config init --profile mobile   # лист с учётом батареи (или без --profile — обычный dev)
veil-cli node run                        # фоновый демон
veil-cli node show                       # статус
veil-cli node stop                       # корректная остановка
```

Полезные команды диагностики: `node health`, `node bandwidth`, `node metrics`,
`node bootstrap-status` (какие есть запасные пути, если IP сида заблокируют).

### Сервер / реле (публичный listener)

Сервер публикует listener, через который другие узлы бутстрапятся. Используйте
профиль `censorship-target` (биндит `wss://0.0.0.0:443`, ставит decoy-SNI,
включает mesh) и повышенную сложность PoW:

```sh
veil-cli config init --profile censorship-target --difficulty 24
# отредактируйте конфиг (адрес listen, SNI, режим [network], пути persist)
veil-cli config show
veil-cli node run
```

Для **защищённого постоянного сервера** (отдельный пользователь `veil`, каталог
данных `/var/lib/veil`, юнит `systemd` и печать публичного join-блоба в конце)
используйте скрипт провижининга со сборкой из исходников:

```sh
sudo PUBLIC_IP=203.0.113.10 LISTEN_PORT=443 ROLE=core \
  ./scripts/install-bootstrap.sh
```

См. [Руководство администратора](../en/admin-guide.md) и
[Operations](../en/OPERATIONS.md) — транспорты, метрики, управление парком.

> **Устойчивость к цензуре.** Бинарники по умолчанию уже включают backend
> ротации TLS-отпечатков `tls-boring`. Для максимальной незаметности изучите
> [p-net.md](../en/p-net.md) и комментарии `censorship-target` в вашем конфиге.

---

## ogate — IP поверх veil

`ogate` пробрасывает реальный IP-трафик через veil (виртуальный LAN). Нужен
TUN-девайс, поэтому запуск под `CAP_NET_ADMIN` / root (или Администратор на Windows).

```sh
ogate gen-config -o ogate.toml          # шаблон с комментариями
# заполните: имя сети, node_id пиров, виртуальные IP
sudo ogate up --config ogate.toml
ogate show                              # разобранный конфиг, без открытия ресурсов
```

Полный справочник: [ogate.md](../en/ogate.md).

---

## oproxy — proxy клиент и сервер

Проброс локального трафика приложений через veil на выходной сервер.

**Клиент** (ваша машина — локальный SOCKS5/HTTP proxy):

```sh
oproxy-client --gen-config > oproxy-client.toml   # задайте server_node_id + [[inbound]] listeners
oproxy-client --config oproxy-client.toml
# направьте браузер/приложение на настроенный SOCKS5/HTTP порт
```

**Сервер** (выходной узел):

```sh
oproxy-server --gen-config > oproxy-server.toml
oproxy-server --config oproxy-server.toml
```

Маршрутизация по цели (veil / direct / block) и failover описаны в
[oproxy.md](../en/oproxy.md).

---

## Опции установщика

Флаги `install.sh` (передавайте после `sh -s --` при пайпе):

| Флаг | Значение |
|------|----------|
| `--all` | Поставить все четыре бинарника |
| `--components a,b` | Конкретный набор |
| `--version X.Y.Z` | Зафиксировать релиз (по умолчанию: latest) |
| `--prefix /usr/local` | Ставить в `<prefix>/bin` (системно) |
| `--bin-dir <dir>` | Ставить прямо в `<dir>` |
| `--libc musl\|gnu` | libc для Linux x86_64 (по умолчанию `musl` — статический, работает везде) |
| `--no-modify-path` | Не трогать профиль шелла |
| `--quickstart` | Сразу init + запуск узла после установки |
| `-y`, `--yes` | Неинтерактивно |
| `--no-verify` | Пропустить проверку sha256 (не рекомендуется) |

`install.ps1` принимает те же параметры PowerShell (`-All`, `-Version`,
`-Components`, `-BinDir`, `-NoModifyPath`, `-Quickstart`, `-NoVerify`). При пайпе
в `iex` настраивайте через env-переменные: `$env:VEIL_COMPONENTS`,
`$env:VEIL_VERSION`, `$env:VEIL_REPO`.

Установка из форка/зеркала — задайте `VEIL_REPO=owner/repo` (env-переменная)
на любой платформе.

---

## Обновление

`veil-cli` умеет обновляться сам из подписанного манифеста оператора:

```sh
veil-cli update check
veil-cli update apply       # проверяет подпись перед заменой бинарника
```

Либо просто перезапустите установщик — он всегда тянет последний релиз. Для
`ogate` / `oproxy` перезапустите установщик (это обычные сервисные бинарники).

---

## Проверка установленного

Установщик сверяет SHA-256 каждого бинарника с опубликованным
`sha256-<triple>.txt` перед установкой. Проверить вручную:

```sh
sha256sum ~/.veil/bin/veil-cli
# сравните с ассетом sha256-<triple>.txt на странице релиза
```

К релизам также прилагается **подписанный `manifest-<triple>.bin`**
(`UpdateManifest`, подписанный ключом релиза из холодного хранилища). Независимый
проверяющий может пересобрать из тегнутого коммита через `scripts/build-release.sh`
и подтвердить байт-в-байт идентичный SHA-256 — см.
[release.yml](../../.github/workflows/release.yml).

---

## Удаление

```sh
# Linux / macOS
rm -rf ~/.veil
# затем уберите строку "# veil" из ~/.profile / ~/.bashrc / ~/.zshrc
```

```powershell
# Windows
Remove-Item -Recurse -Force $env:USERPROFILE\.veil
# затем уберите каталог bin из PATH (Система > Переменные среды)
```

Данные узла (конфиг + identity + состояние) лежат в конфиг-каталоге платформы;
путь печатает `veil-cli config locate`, если хотите стереть и их.

---

## Сборка из исходников

Нужна только для платформ без готового бинарника (например, **Intel macOS**) или
для разработки. Дефолтные фичи тянут **BoringSSL (`tls-boring`)** и
**RocksDB (`rocksdb-cold`)**, поэтому нужен C/C++-тулчейн:

```sh
# Зависимости Debian/Ubuntu для дефолтной (BoringSSL + RocksDB) сборки:
sudo apt-get install -y cmake golang-go nasm ninja-build build-essential

git clone https://github.com/veilnetwork/veil
cd veil
cargo build --release --bin veil-cli --bin ogate --bin oproxy-client --bin oproxy-server \
  --features veil-bootstrap/production-seeds
# бинарники появятся в target/release/
```

Для воспроизводимых подписанных релизов используйте `scripts/build-release.sh --target <triple>`.
Кросс-сборка статического Linux-бинарника с macOS — см. `scripts/cross-build-linux-musl.sh`.

---

## Поддерживаемые платформы

Готовые бинарники публикуются для:

| Triple | Примечания |
|--------|------------|
| `x86_64-unknown-linux-musl` | **по умолчанию для Linux x86_64** — статический, любой дистрибутив |
| `x86_64-unknown-linux-gnu` | сборка под glibc (`--libc gnu`) |
| `aarch64-unknown-linux-gnu` | ARM64 Linux |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows 10/11 (x64) |

Для Intel macOS (`x86_64-apple-darwin`) и ARM64 Windows готовых бинарников нет —
[соберите из исходников](#сборка-из-исходников) или запускайте x64-сборку под эмуляцией.

---

## Безопасность `curl … | sh`

Скрипт качается по HTTPS (TLS 1.2+), сверяет SHA-256 каждого бинарника перед
установкой, не требует root для дефолтной пользовательской установки и трогает
только `~/.veil` плюс строку `PATH` в профиле шелла. Если хотите прочитать
перед запуском — скачайте сначала:

```sh
curl -fsSLO https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.sh
less install.sh        # ревью
sh install.sh
```
