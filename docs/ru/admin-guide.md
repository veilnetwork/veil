# Руководство администратора

## Обзор

Узел Veil настраивается через единственный TOML-файл — обычный текстовый файл
настроек. В нём собрано всё, что нужно знать узлу.

Управлять работающим узлом можно двумя способами. Либо командой `veil-cli`, либо
напрямую — через админ-протокол узла. Это простой канал «запрос — ответ»: он
передаёт JSON по локальному сокету (программному каналу связи в пределах одной
машины). Не путайте его с протоколом OVL1 (его называют *сетевым протоколом*,
по-английски *wire protocol*) — компактным двоичным форматом, на котором узлы
общаются между собой. Админ-протокол — для вас и ваших инструментов; сетевой
протокол — для самих узлов.

### Как подключается админ-протокол

Узел принимает административные команды по локальному каналу. Какой именно — вы
выбираете в `global.admin_socket`. Вариантов два.

Первый — *доменный сокет Unix*: особый файл на диске, через который программы на
одной машине общаются друг с другом. Это вариант по умолчанию на Linux и macOS:
`unix:///path/to/admin.sock`.

Второй — *TCP-loopback*: сетевое соединение, которое не выходит за пределы вашей
машины. Оно остаётся на `127.0.0.1` — адресе, по которому компьютер обращается
сам к себе: `tcp://127.0.0.1:0?runtime_dir=/abs/path`. На Windows это
единственный вариант, потому что доменных сокетов Unix там нет. Этот вариант
(TCP-loopback) добавил эпик 451.

| Бэкенд | Конфиг | Где живут файлы | Проверка равенства UID |
|--------|--------|-----------------|------------------------|
| Unix | `unix:///abs/admin.sock` | Сам сокет-файл (mode `0o600`) | `SO_PEERCRED` / `getpeereid` |
| TCP-loopback | `tcp://127.0.0.1:0?runtime_dir=…` | `admin.port` + `admin.token` в `runtime_dir` | 32-байтный токен (`subtle::ct_eq`) |

TCP-бэкенд слушает `127.0.0.1` и только его. `localhost` и `::1` (тот же
локальный адрес, записанный иначе) тоже допустимы, а любой другой адрес
отклоняет валидатор. Раздавать административные команды на публичном порту
небезопасно даже при наличии токена, поэтому узел просто этого не делает.

Клиенты — `veil-cli` и любое прямое подключение — находят нужный канал через одну
вспомогательную функцию, `admin_socket_path(config)`. Для TCP она возвращает
подставной путь `runtime_dir/admin.anchor`. Само соединение затем устанавливает
`connect_admin_client_any`: он ищет рядом с этим путём `admin.port` и
`admin.token`, и если находит — идёт по TCP, а если нет — использует запасной
путь через сокет Unix.

---

## Конфигурационный файл

По умолчанию узел ищет файл конфигурации здесь:
- Linux: `~/.config/veil/config.toml`
- macOS: `~/Library/Application Support/veil/config.toml`
- Windows: `%APPDATA%\veil\config.toml`

Чтобы указать путь самому: `veil-cli --config /etc/veil/config.toml node run`

> Нужны все секции и поля конфига — с типами, значениями по умолчанию и описанием
> каждого параметра? Полный список — в **[Справочнике конфигурации](config-reference.md)**.

---

## Личность узла и управление ключами

У каждого узла есть *личность* — пара криптографических ключей: открытый, который
видят все, и закрытый, который держите только вы. Адрес узла вычисляется из
открытого ключа, так что личность — это и есть узел. Берегите закрытый ключ:
потеряете его — потеряете и узел.

### Алгоритмы подписи

| Алгоритм | Wire-байт | Ключ pub | Ключ priv | Подпись | Замечание |
|----------|-----------|---------|---------|---------|-----------|
| Ed25519 | 0 | 32 байта | 32 байта | 64 байта | По умолчанию |
| Falcon512 | 2 | 897 байт | 1281 байт | 666 байт | Постквантовый |

У каждого алгоритма есть однобайтовая метка — сетевой байт `algo`. Он идёт по
сети, чтобы другая сторона знала, какой алгоритм её ждёт. То же значение
используется в `IdentityPayload`, `DeletePayload`, mesh-beacon и PEX-подписи.
Одно исключение: в рукопожатии сессии (`SessionMsg::KeyAgreement`) нумерация своя
— 1 = Ed25519, 2 = Falcon512 (см. `node/session/handshake.rs::algo_to_u8`).

### Генерация ключей

```bash
veil-cli key gen
veil-cli key gen --algo falcon512
```

**Создание личности с nonce доказательства работы** (рекомендуется при
первоначальной настройке):

```bash
veil-cli config init --difficulty 16
```

*Доказательство работы* — небольшая задачка, которую узел решает, чтобы получить
свою личность: для честного участника она дёшева, а для спамера, штампующего
подделки, дорога. Ответ на задачку — это число, которое называют *nonce*.
Сложность `difficulty` задаёт, насколько задачка трудна: это количество ведущих
нулевых битов, которое должно быть у BLAKE3-хэша nonce. При `difficulty=16`
ожидается около 65K попыток — меньше миллисекунды на современном оборудовании.

### Безопасность ключей

- Держите файл конфига доступным только владельцу: `chmod 600 ~/.config/veil/config.toml`
- Закрытый ключ лежит в файле открытым текстом. Для боевого узла защитите его
  шифрованием файловой системы или аппаратным модулем безопасности (HSM —
  отдельным устройством, которое хранит ключи и наружу их не выпускает).
- **Никогда** не публикуйте `private_key`.

### Смена ключей

Замена ключа меняет `node_id`, поэтому для сети это всё равно что появление
нового узла:

```bash
veil-cli key gen --output > new_keys.txt   # печатает пару в stdout, не трогая конфиг
# Обновить public_key, private_key, пересчитать nonce
veil-cli config init --force
```

---

## Управление слушателями и пирами

*Слушатель* (входящий адрес) — это адрес, который ваш узел открывает, чтобы другие
могли подключаться *к* нему. *Пир* (сосед) — другой узел, к которому ваш
обращается *сам*. Слушатели — это то, как вас находят; пиры — это с кем вы
общаетесь.

### CLI для слушателей

```bash
veil-cli listen add tcp://0.0.0.0:9000
veil-cli listen del LISTEN_ID
veil-cli listen list
```

Ещё несколько флагов для `listen add`. `--advertise URI` позволяет объявлять не
тот адрес, который узел слушает, а другой — это удобно, когда узел стоит за
обратным прокси (промежуточным сервером, который передаёт ему соединения). Есть
также `--relay NODE_ID_BASE64` и `--tls-cert`, `--tls-key`, `--tls-ca-cert` для
зашифрованных слушателей `tls://` и `wss://`.

### Транспорты (способы передачи)

*Транспорт* (способ передачи) — это просто то, как байты физически путешествуют:
обычный TCP, зашифрованный TLS, QUIC и так далее. Какой из них взять, вы
выбираете схемой в начале адреса слушателя (той самой частью `tcp://`). Вот
перечень:

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

Когда тот, кому вы пишете, не в сети, его узел ничего принять не может. На этот
случай есть *почтовый ящик* (mailbox): core-узел придержит сообщение, пока
получатель не вернётся в сеть и не заберёт его. По умолчанию ящик выключен, а
включается одним флагом:

```toml
[mailbox]
enabled = true
```

Выбирать, где он хранит данные, не нужно. При `enabled = true` узел всегда
открывает встроенное хранилище redb по единственному фиксированному пути
`<veil_dir>/mailbox/blobs.db`. (redb — небольшая встроенная база данных;
*долговечное* (durable) означает, что данные переживут сбой, а *транзакционное* —
что каждое изменение применяется целиком или не применяется вовсе.) Полей
`backend`, `data_dir` и `strict_backend` в секции `[mailbox]` нет — они не
существуют.

Настроить можно только квоты, TTL, ограничение частоты и push-уведомления.
(*Квота* ограничивает, сколько можно хранить; *TTL* (от англ. «time to live»,
время жизни) — сколько сообщение хранится, прежде чем его удалят; *ограничение
частоты* задаёт, как быстро могут приходить новые сообщения.) Оставите значение
нулём — узел возьмёт значение по умолчанию из крейта (Rust-библиотеки)
`veil-mailbox`:

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

*Метрики* — это счётчики и измерители, которые узел ведёт о самом себе: сколько
открыто сессий, сколько прошло байт и так далее. По ним удобно следить за
состоянием узла во времени.

### Настройка экспортера

Секция `[metrics]` включает *экспортер* — небольшую встроенную веб-страницу,
которая публикует эти числа в формате Prometheus (популярного инструмента
мониторинга), чтобы он мог их считывать.

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

`listen` — это TransportUri, и он должен начинаться со схемы `tcp://`, иначе
конфиг не пройдёт проверку.

### Получение метрик

```bash
# Через CLI
veil-cli node metrics

# Через HTTP (Prometheus scrape)
curl http://127.0.0.1:9090/metrics
```

### Доступные счётчики

Полный список лежит в коде, в `NodeMetrics::render_prometheus`
([observability.rs](../../crates/veil-observability/src/lib.rs)). Каждое имя несёт
префикс `veil_`. Основные группы — ниже. (*Счётчик* (counter) только растёт — это
сумма с момента запуска; *измеритель* (gauge) ходит вверх-вниз и показывает
значение прямо сейчас.)

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

> **Сколько в почтовом ящике.** Одного числа в Prometheus нет: сколько блобов
> сейчас лежит в почтовом ящике. Чтобы его увидеть, посмотрите поле
> `mailbox_entries` в дампе состояния admin HTTP API.

---

## Admin API — административный сокет

**Адрес.** Доменный сокет Unix (по умолчанию на Linux и macOS) либо TCP-loopback
под защитой токена (единственный вариант на Windows, где сокетов Unix нет). Путь
или URI задаётся в `global.admin_socket`; оба варианта разобраны выше, в разделе
«Как подключается админ-протокол».

**Протокол.** Обычные «запрос — ответ»: клиент шлёт строку JSON, узел отвечает
такой же строкой, каждая завершается переводом строки. На TCP-бэкенде есть один
лишний шаг в начале. Первым сообщением клиент отправляет 32-байтный токен,
прочитанный из `runtime_dir/admin.token`. Узел сравнивает его за *постоянное
время* — то есть проверка длится одинаково, верен токен или нет, чтобы атакующий
не мог ничего узнать по задержке. Только при совпадении узел начинает отвечать;
иначе кладёт трубку.

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

Те же самые команды есть и под `veil-cli sessions ban/unban/banned` — оба
названия меняют одно и то же общее состояние.

### Горячая перезагрузка конфига

Конфиг узла можно поменять, не перезапуская сам узел. Это *горячая перезагрузка*:
работающий узел на ходу перечитывает свой файл конфигурации.

```bash
# Через admin API (рекомендуется — адресует именно запущенный daemon)
veil-cli node reload

# Или SIGHUP напрямую: под systemd
systemctl reload veil        # ExecReload см. в unit ниже
```

Небольшое предупреждение про `pkill -HUP veil-cli`: он сделает то, что нужно,
только если в системе запущена ровно одна копия бинарника и это сам узел, а не
CLI-клиент. Для боевой системы это слишком ненадёжно — пользуйтесь одной из двух
команд выше.

---

## Настройка systemd-сервиса

На Linux узел обычно хочется запускать при старте системы и перезапускать, если
он вдруг упал. Этим занимается *systemd* — менеджер служб, встроенный в
большинство дистрибутивов Linux. Службу описывают в небольшом файле, который
называют *юнитом* (unit), — вот такой пример:

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

Если что-то идёт не так, найдите подходящий симптом и разберите его по шагам.
Каждый раздел начинается с самой частой причины.

### Узел не запускается

Чаще всего дело в конфиге. Сначала проверьте его, а потом понаблюдайте за логами,
пока узел поднимается:

```bash
# Проверить конфиг
veil-cli config validate

# Посмотреть логи
veil-cli --config /etc/veil/config.toml node run
# или через journalctl если systemd
```

### Нет входящих соединений

К вам никто не может подключиться. Проверьте по порядку:

1. Открыт ли брандмауэр (файрвол) на нужных портах?
2. Есть ли в конфиге блок `[[listen]]`?
3. Что говорит слушатель? Запустите `veil-cli listen list`.

### Нет исходящих соединений

Вы не можете ни до кого достучаться. Проверьте по порядку:

1. Добавлены ли блоки `[[peers]]`?
2. В порядке ли транспортный URI? Попробуйте `veil-cli debug transport connect URI`.
3. Достаёте ли вы до пира вообще? Попробуйте `veil-cli debug peers connect PEER_ID`.

### Высокое потребление памяти

Посмотрите лимиты в `[capacity]` и `[abuse]`. На перегруженном шлюзе их ужесточение
помогает:

```toml
[capacity]
max_relay_sessions = 512

[abuse]
rate_limit_fps = 20.0
```

### Узел не виден в DHT

DHT — это общий справочник адресов сети, по которому другие узлы вас находят. Если
вас в нём нет:

- Убедитесь, что в `[[peers]]` указан хотя бы один Core-узел.
- У узла должен быть адрес `[[listen]]`, до которого реально достучаться из
  открытого интернета.
- Проверьте таблицу маршрутизации: `veil-cli node dht routing`.

---

## Запуск как сервис

Следить за узлом вручную не хочется. Лучше поручить его тому, чем ваша
операционная система запускает фоновые программы, — чтобы она же перезапускала их
после перезагрузки или сбоя.

### Linux / macOS — systemd / launchd

На Unix-системах узел работает как обычная фоновая программа (*демон*). Его
встраивают в системный менеджер служб — systemd на Linux или launchd на macOS
(его аналог, который настраивается небольшим файлом — *plist*). Вот шаблонный
юнит systemd:

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

На Windows узел умеет регистрироваться как обычная служба Windows через Service
Control Manager (SCM) — ту часть Windows, что запускает фоновые службы и следит за
ними. После регистрации служба автоматически стартует при загрузке,
останавливается при выключении и видна в `services.msc` и `Get-Service VeilNode`.

**Установка** (нужны права администратора):

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

**Что полезно знать:**

- По умолчанию служба работает от имени `LocalSystem` — мощной встроенной учётной
  записи. Чтобы запускать её от менее привилегированного пользователя,
  отредактируйте службу после установки:
  ```powershell
  sc config VeilNode obj= ".\veil_user" password= "..."
  ```
- Путь к конфигу зашивается в `ImagePath` службы при установке. Поэтому если вы
  потом переместите конфиг, удалите службу и установите её заново.
- `service run` — точка входа, которую вызывает SCM; в `--help` она скрыта. Сами
  не запускайте её — используйте `install`, а затем `Start-Service`.
- Корректное завершение: при `Stop-Service` SCM посылает сигнал
  `ServiceControl::Stop`. Служба помечает себя как `StopPending`, дожидается, пока
  узел остановится (в том числе сбросит на диск баны, найденных пиров и прочее,
  чтобы ничего не потерять), и только потом сообщает `Stopped`.
