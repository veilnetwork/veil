# Руководство администратора

## Обзор

Узел OVL1 настраивается через единый TOML-файл. Административное управление выполняется через `veil-cli` или напрямую по JSON-over-socket админ-протоколу (не путать с бинарным OVL1 wire-протоколом между узлами).

### Транспорт admin-протокола

Епик 451 добавил TCP-loopback backend: `global.admin_socket` может быть
`unix:///path/to/admin.sock` (Linux/macOS по умолчанию) или
`tcp://127.0.0.1:0?runtime_dir=/abs/path` (обязательный на Windows — Unix
доменные сокеты там недоступны).

| Бэкенд | Конфиг | Где живут файлы | Проверка равенства UID |
|--------|--------|-----------------|------------------------|
| Unix | `unix:///abs/admin.sock` | Сам сокет-файл (mode `0o600`) | `SO_PEERCRED` / `getpeereid` |
| TCP-loopback | `tcp://127.0.0.1:0?runtime_dir=…` | `admin.port` + `admin.token` в `runtime_dir` | 32-байтный токен (`subtle::ct_eq`) |

TCP-бэкенд биндит `127.0.0.1` и только `127.0.0.1`: `localhost`, `::1` тоже
допустимы, любой другой host отклоняется валидатором (админ через публичный
порт небезопасен даже с токеном).

Клиенты (`veil-cli`, прямое подключение) получают обе формы через единый
`admin_socket_path(config)` — на TCP он возвращает синтетический
`runtime_dir/admin.anchor`; реальное соединение делается через
`connect_admin_client_any`, который ищет `admin.port` + `admin.token`
рядом с anchor и идёт по TCP, либо падает обратно на Unix-сокет.

---

## Конфигурационный файл

Файл конфигурации располагается по умолчанию в:
- Linux: `~/.config/veil/config.toml`
- macOS: `~/Library/Application Support/veil/config.toml`
- Windows: `%APPDATA%\veil\config.toml`

Задать путь явно: `veil-cli --config /etc/veil/config.toml node run`

> Исчерпывающий справочник всех секций и полей конфига с типами, значениями по умолчанию и описанием каждого параметра — см. **[Справочник конфигурации](config-reference.md)**.

---

## Идентичность узла и управление ключами

### Алгоритмы подписи

| Алгоритм | Wire-байт | Ключ pub | Ключ priv | Подпись | Замечание |
|----------|-----------|---------|---------|---------|-----------|
| Ed25519 | 0 | 32 байта | 32 байта | 64 байта | По умолчанию |
| Falcon512 | 2 | 897 байт | 1281 байт | 666 байт | Постквантовый |

Wire-байт `algo` соответствует значениям в `IdentityPayload`, `DeletePayload`, mesh-beacon
и PEX-подписи. В session-handshake (`SessionMsg::KeyAgreement`) используется отдельная
конвенция: 1 = Ed25519, 2 = Falcon512 (см. `node/session/handshake.rs::algo_to_u8`).

### Генерация ключей

```bash
veil-cli key gen
veil-cli key gen --algo falcon512
```

**Создание identity с PoW-nonce** (рекомендуется при первоначальной настройке):

```bash
veil-cli config init --difficulty 16
```

Сложность `difficulty` — количество ведущих нулевых битов в BLAKE3-хэше nonce. При `difficulty=16` ожидается ~65K итераций (< 1 мс на современном оборудовании).

### Безопасность ключей

- Файл конфига должен быть доступен только владельцу: `chmod 600 ~/.config/veil/config.toml`
- Приватный ключ хранится в открытом виде — используйте шифрование ФС или HSM для production
- **Никогда** не публикуйте `private_key`

### Смена ключей

Смена ключа меняет `node_id`, что равносильно созданию нового узла:

```bash
veil-cli key gen --output > new_keys.txt   # печатает пару в stdout, не трогая конфиг
# Обновить public_key, private_key, пересчитать nonce
veil-cli config init --force
```

---

## Управление слушателями и пирами

### CLI для слушателей

```bash
veil-cli listen add tcp://0.0.0.0:9000
veil-cli listen del LISTEN_ID
veil-cli listen list
```

Дополнительные флаги `listen add`: `--advertise URI` (анонсируемый адрес при reverse proxy),
`--relay NODE_ID_BASE64`, а также `--tls-cert/--tls-key/--tls-ca-cert` для `tls://`/`wss://` слушателей.

### Транспорты

| Схема | Протокол | Безопасность | Особенности |
|-------|----------|--------------|-------------|
| `tcp` | TCP | Нет (OVL1-шифрование поверх) | Простой, быстрый |
| `tls` | TCP + TLS 1.3 | TLS-сертификат | Рекомендуется для публичных узлов |
| `quic` | UDP + QUIC | TLS внутри QUIC | Быстрый handshake, мультиплексирование |
| `ws` | HTTP WebSocket | Нет | Для обхода firewall через порт 80/443 |
| `wss` | HTTPS WebSocket | TLS | WebSocket с TLS |
| `unix` | Unix domain socket | Права файла | Только локальные IPC-соединения |

### CLI для пиров

```bash
# Добавить пир: PUBLIC_KEY, NONCE и TRANSPORT — позиционные аргументы
veil-cli peers add \
  --algo ed25519 \
  "BASE64_PUBLIC_KEY==" \
  "BASE64_POW_NONCE==" \
  "tls://core.example.com:9443"

# Удалить (по peer_id из `peers list`, либо --by-node-id / --by-public-key)
veil-cli peers del PEER_ID
veil-cli peers del --by-node-id HEX_NODE_ID

# Список
veil-cli peers list
```

---

## Mailbox — хранилище сообщений

Core-узлы могут хранить сообщения для офлайн-получателей. Mailbox выключен по умолчанию и включается одним флагом:

```toml
[mailbox]
enabled = true
```

Выбора backend'а нет: при `enabled = true` рантайм всегда открывает встроенное хранилище redb по фиксированному пути `<veil_dir>/mailbox/blobs.db` (durable, транзакционное). Никаких полей `backend`, `data_dir`, `strict_backend` в секции `[mailbox]` не существует.

Настраиваются только квоты, TTL, лимит частоты и push-уведомления (при нулевых значениях используются дефолты крейта `veil-mailbox`):

| Поле | Назначение | По умолчанию |
|------|------------|--------------|
| `enabled` | Главный выключатель | `false` |
| `quota_per_receiver_bytes` | Квота на получателя (байты) | 100 МиБ |
| `quota_global_bytes` | Глобальная квота на узел (байты) | 10 ГиБ |
| `quota_per_sender_bytes` | Квота на отправителя (байты) | 10 МиБ |
| `ttl_secs` | TTL хранения блоба (сек) | 7 дней |
| `rate_limit_per_minute` | Лимит put'ов в минуту на получателя | 60 |
| `require_capability_token` | Требовать capability-токен на PUT | `false` |
| `[mailbox.push]` | Учётные данные провайдеров push (FCM/APNs) | пусто (только лог) |

Подробнее о полях секции `[mailbox]` — в [Справочнике конфигурации](config-reference.md#mailbox).

---

## Метрики

### Настройка экспортера

Секция `[metrics]` включает HTTP-экспортер в Prometheus-формате:

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

`listen` — это TransportUri (должна содержать схему `tcp://`), иначе конфиг не пройдёт валидацию.

### Получение метрик

```bash
# Через CLI
veil-cli node metrics

# Через HTTP (Prometheus scrape)
curl http://127.0.0.1:9090/metrics
```

### Доступные счётчики

Полный список формируется в `NodeMetrics::render_prometheus`
([observability.rs](../../crates/veil-observability/src/lib.rs)). Все имена
экспортируются с префиксом `veil_`. Ниже — основные группы.

| Группа | Метрика | Тип | Описание |
|--------|---------|-----|----------|
| Transport | `veil_configured_peers` | gauge | Число `[[peers]]` в конфиге |
| Transport | `veil_active_sessions` | gauge | Текущих активных сессий |
| Transport | `veil_inbound_sessions_total` | counter | Установлено входящих сессий |
| Transport | `veil_outbound_connect_attempts_total` | counter | Попыток исходящего коннекта |
| Transport | `veil_outbound_connect_failures_total` | counter | Неудачных исходящих коннектов |
| Transport | `veil_transport_bytes_rx_total` | counter | Байт принято на транспорте |
| Transport | `veil_transport_bytes_tx_total` | counter | Байт отправлено на транспорте |
| Session | `veil_session_handshake_failures_total` | counter | Отказов в handshake |
| Delivery | `veil_mailbox_fetches_total` | counter | MAILBOX_FETCH операций |
| Delivery | `veil_delivery_rejects_total` | counter | Отвергнутых Delivery-фреймов |
| Delivery | `veil_chunks_reassembled_total` | counter | Собранных chunked-трансферов |
| Delivery | `veil_multi_path_sends_total` | counter | Параллельных рассылок по путям |
| DHT | `veil_dht_store_total` | counter | STORE операций в DHT |
| DHT | `veil_dht_lookup_total` | counter | LOOKUP операций в DHT |
| Crypto | `veil_decrypt_failures_total` | counter | Ошибок E2E-дешифрования |
| Storage | `veil_storage_evictions_total` | counter | Вытеснений из storage |
| Routing | `veil_route_miss_total` | counter | Cache-miss в route-cache |
| Routing | `veil_discovery_triggered_total` | counter | Запусков route-discovery |
| Routing | `veil_route_recovery_total` | counter | Восстановлений маршрута после miss |
| Routing | `veil_route_cache_hits_total` | counter | Cache-hit при форвардинге |
| Routing | `veil_network_reachability_score` | gauge | Доля успешных recovery в окне (0.0–1.0) |
| Routing | `veil_route_selection_avg_rtt_ms` | gauge | Средний RTT выбранных маршрутов (мс) |
| Routing | `veil_vivaldi_prediction_error_ms` | gauge | Средняя ошибка предсказания Vivaldi (мс) |
| Routing | `veil_vivaldi_coord_x` / `_y` / `_height` / `_error` | gauge | Локальная Vivaldi-координата (синтетические, значимы только как расстояния) |
| Mesh | `veil_mesh_relay_hops_total` | counter | Хопов через mesh-relay |
| Mesh | `veil_gossip_announces_rx_total` | counter | Принятых ROUTE_ANNOUNCE |
| DHT-routing | `veil_recursive_relay_initiated_total` | counter | Инициированных RecursiveRelay |
| DHT-routing | `veil_recursive_relay_forwarded_total` | counter | Транзитных RecursiveRelay-хопов |
| DHT-routing | `veil_recursive_relay_delivered_total` | counter | Доставленных RecursiveRelay |
| Abuse | `veil_rate_limit_drops_total` | counter | Фреймов отброшено rate-limiter'ом |
| Abuse | `veil_backpressure_received_total` | counter | Полученных BACKPRESSURE |
| Abuse | `veil_ban_actions_total` | counter | Применённых банов |
| RT | `veil_rt_frames_total` / `_rx_total` / `_tx_total` | counter | Реалтайм-фреймов (сумма / RX / TX) |
| RT | `veil_rt_seq_gaps_total` | counter | Пропусков sequence-number в RT |
| App | `veil_app_msg_channel_full_total` | counter | Переполнений IPC-канала |
| App | `veil_app_msg_channel_closed_total` | counter | Доставок в закрытый канал |
| Session-queue | `veil_session_tx_drops_total` | counter | Сброшено из per-session TX-очереди |
| Session-queue | `veil_session_outbox_drops_total` | counter | Сброшено из SessionOutbox |
| IPC | `veil_ipc_delivery_drops_total` | counter | Сброшено в IPC-канал клиента |
| Sleep | `veil_sleeping_recipients` | gauge | Получателей в sleep-state на хосте |
| Sleep | `veil_sleep_advertisements_accepted_total` | counter | Принятых SleepAdvertisement |
| Sleep | `veil_sleep_advertisements_emitted_total` | counter | Отправленных SleepAdvertisement |
| Sleep | `veil_wakeup_fetches_total` | counter | Wake-up MAILBOX_FETCH при открытии сессии |

> **Глубина mailbox.** Текущее число блобов в mailbox в Prometheus не
> экспортируется — оно доступно только через дамп состояния admin HTTP API
> в поле `mailbox_entries`.

---

## Admin API — административный сокет

**Адрес:** Unix domain socket (по умолчанию на Linux/macOS) или TCP-loopback с
токен-аутентификацией (на Windows — обязательно, т.к. Unix-сокеты недоступны).
Путь/URI задаётся `global.admin_socket`; см. раздел "Транспорт admin-протокола"
выше.

**Протокол:** JSON-запрос/ответ поверх socket, newline-terminated.  Для TCP-бэкенда
первым кадром клиент отправляет 32-байтный бинарный токен, прочитанный из
`runtime_dir/admin.token` — только после успешной константно-временной
проверки сервер начинает обслуживать admin-протокол; иначе соединение
сбрасывается.

### Инспекция узла

```bash
# Состояние узла
veil-cli node show

# Активные сессии
veil-cli sessions list

# Маршруты (route cache)
veil-cli node routes

# DHT
veil-cli node dht list
veil-cli node dht get HEX_KEY         # KEY — позиционный аргумент, 64 hex-символа
veil-cli node dht routing             # Kademlia routing table

# Записи discovery
veil-cli node discovery-list

# Gateway: подключённые leaf-узлы
veil-cli node gateway-list
```

### Диагностика

```bash
# Ping к удалённому узлу через veil
veil-cli debug ping HEX_NODE_ID --count 5 --interval 1000 --timeout 5000

# Traceroute
veil-cli debug trace HEX_NODE_ID --max-hops 16 --timeout 5000

# Захват фреймов (для отладки)
veil-cli debug capture --limit 100
veil-cli debug capture --node-id HEX --family 3   # только Delivery-фреймы

# Тест подключения к конкретному пиру (peer_id из `peers list`)
veil-cli debug peers connect PEER_ID

# Тест приёма на слушателе (listen_id из `listen list`)
veil-cli debug node accept LISTEN_ID
```

### Управление блокировками

```bash
# Заблокировать узел (NODE_ID — 64 hex-символа)
veil-cli peers ban NODE_ID

# Разблокировать
veil-cli peers unban NODE_ID

# Список активных банов
veil-cli peers banned
```

Эти же подкоманды доступны и под `veil-cli sessions ban/unban/banned` — они делят одно backend-состояние.

### Горячая перезагрузка конфига

```bash
# Через admin API (рекомендуется — адресует именно запущенный daemon)
veil-cli node reload

# Или SIGHUP напрямую: под systemd
systemctl reload veil        # ExecReload см. в unit ниже
```

`pkill -HUP veil-cli` сработает только если в системе единственный запущенный
процесс бинарника и он не CLI-клиент — в продакшне полагаться на это не стоит.

---

## Настройка systemd-сервиса

```ini
# /etc/systemd/system/veil.service
[Unit]
Description=OVL1 Veil Node
After=network.target

[Service]
Type=simple
User=veil
Group=veil
ExecStart=/usr/local/bin/veil-cli --config /etc/veil/config.toml node run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable veil
systemctl start veil
systemctl status veil
journalctl -u veil -f
```

---

## Устранение неполадок

### Узел не запускается

```bash
# Проверить конфиг
veil-cli config validate

# Посмотреть логи
veil-cli --config /etc/veil/config.toml node run
# или через journalctl если systemd
```

### Нет входящих соединений

1. Проверьте что firewall открыт на нужных портах
2. Убедитесь что `[[listen]]` блок есть в конфиге
3. Проверьте статус слушателей: `veil-cli listen list`

### Нет исходящих соединений

1. Проверьте что `[[peers]]` блоки добавлены
2. Проверьте транспортный URI: `veil-cli debug transport connect URI`
3. Проверьте связность: `veil-cli debug peers connect PEER_ID`

### Высокое потребление памяти

Проверьте лимиты в `[capacity]` и `[abuse]`. На перегруженном шлюзе:

```toml
[capacity]
max_relay_sessions = 512

[abuse]
rate_limit_fps = 20.0
```

### Узел не виден в DHT

- Убедитесь что хотя бы один Core-узел добавлен в `[[peers]]`
- Узел должен иметь публично доступный `[[listen]]` адрес
- Проверьте: `veil-cli node dht routing`

---

## Запуск как сервис

### Linux / macOS — systemd / launchd

На Unix-системах veil работает как обычный daemon; интеграция с
системным супервизором делается через systemd unit (Linux) или
launchd plist (macOS).  Шаблонный unit:

```ini
[Unit]
Description=Veil Node
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/veil-cli --config /etc/veil/config.toml node run --foreground
Restart=on-failure
User=veil

[Install]
WantedBy=multi-user.target
```

### Windows — Service Control Manager

На Windows veil умеет регистрироваться как нативный сервис через
SCM.  Сервис автоматически стартует при загрузке, останавливается при
shutdown и виден в `services.msc` / `Get-Service VeilNode`.

**Установка** (требует админских прав):

```powershell
# Из PowerShell от администратора.
veil-cli service install --config C:\ProgramData\veil\config.toml

# Сервис установлен как AutoStart.  Запустить сразу:
sc start VeilNode

# Или через PowerShell:
Start-Service VeilNode
```

**Контроль:**

```powershell
Get-Service VeilNode         # Status check
Stop-Service VeilNode        # Graceful stop (SCM sends ServiceControl::Stop)
Start-Service VeilNode
```

**Деинсталляция** (останавливает если запущен):

```powershell
veil-cli service uninstall
```

**Детали реализации:**

- Сервис логинится как `LocalSystem` по умолчанию.  Для запуска под
  менее привилегированной учёткой отредактируйте после install:
  ```powershell
  sc config VeilNode obj= ".\veil_user" password= "..."
  ```
- Config path зашивается в service `ImagePath` при install.  Если
  config потом переместить — уннинстальте и переустановите сервис.
- `service run` — entry invoked by SCM, скрыт от `--help`.  Операторы
  не должны вызывать его напрямую; используйте `install` +
  `Start-Service`.
- Graceful shutdown: на `Stop-Service` SCM посылает `ServiceControl::Stop`,
  сервис flip-ает статус в `StopPending`, ждёт остановки node runtime
  (включая fsync bans/peers_discovered/etc persist), затем `Stopped`.
