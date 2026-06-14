# Руководство по мониторингу

> Справочник оператора для наблюдения за работающим узлом: за чем смотреть,
> почему это важно и когда поднимать оповещение. Читайте вместе с
> [OPERATIONS.md](OPERATIONS.md) (развёртывание) и
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (реагирование на инциденты).

## Настройка экспортёра

Узел сообщает о своём состоянии в виде **метрик** — именованных чисел вроде
«активных сессий» или «неудавшихся подключений», которые вы измеряете во
времени. Veil отдаёт их в формате, который читает [Prometheus](https://prometheus.io).
Prometheus — это инструмент, который собирает метрики со множества машин и
хранит их, чтобы можно было строить графики и слать оповещения. Компонент,
который их отдаёт, называют экспортёром.

Чтобы включить экспортёр, добавьте в `config.toml`:

```toml
[metrics]
listen      = "tcp://127.0.0.1:9090"   # bind URI (scheme required); bind to 0.0.0.0 only behind a firewall
path        = "/metrics"          # default
auth_token  = "abcd1234..."       # optional bearer token; clients send `Authorization: Bearer …`
```

Перезапустите узел и проверьте, что точка отдачи отвечает:

```bash
curl http://127.0.0.1:9090/metrics
# (с токеном)
curl -H "Authorization: Bearer abcd1234..." http://127.0.0.1:9090/metrics
```

Сбор (scrape) — это одно чтение точки отдачи со стороны Prometheus. Каждая
метрика появляется один раз за сбор. Единственная метка, которую к ней
добавляют, — `instance`; её проставляет сам Prometheus, чтобы пометить, с какого
узла снято значение. Ниже встречаются два вида метрик. **Счётчик** (counter)
только растёт — он считает события с момента запуска (здесь это всегда `u64`).
**Датчик** (gauge) — это текущее значение, которое может и расти, и падать, как
указатель уровня топлива; датчики бывают `f64` (координаты Vivaldi) или `usize`.

## Справочник метрик

Разделы ниже примерно упорядочены по тому, как часто к ним обращаются.

### Жизнеспособность и ёмкость (liveness / capacity)

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_active_sessions` | gauge | Сессии OVL1, установленные прямо сейчас | `> 0.8 × max_concurrent` в течение 5 м |
| `veil_configured_peers` | gauge | Число записей `[[peers]]` | резкое падение = сбой при перечитывании конфигурации |
| `veil_inbound_sessions_total` | counter | Все входящие рукопожатия с момента запуска | всплеск частоты = сканирование или злоупотребление |
| `veil_outbound_connect_attempts_total` | counter | Все исходящие попытки подключения с момента запуска | всплеск частоты = текучка соседей или нестабильность сети |
| `veil_outbound_connect_failures_total` | counter | Неудавшиеся исходящие подключения | доля неудач > 50 % за 10 м = вышестоящий сосед лёг |
| `veil_session_handshake_failures_total` | counter | Ошибки входящего рукопожатия (аутентификация / шифр / протокол) | всплеск частоты = сканер или расхождение версий |

### Маршрутизация (routing) — самый просматриваемый раздел

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_route_miss_total` | counter | Кадры DELIVERY, для которых нет маршрута к получателю | `> 100/s` в течение 5 м → фрагментация сети; проверьте DHT |
| `veil_discovery_triggered_total` | counter | Запущен реактивный поиск маршрута (RecursiveQuery) | резкий всплеск совпадает со всплеском route_miss |
| `veil_route_recovery_total` | counter | Удачные перестроения маршрута после гибели основного транзита | высокий = нестабильный вышестоящий сосед |
| `veil_route_selection_avg_rtt_ms` | gauge (мс) | Средний RTT (время обхода туда-обратно) выбранного следующего транзита | растущий тренд = перегрузка сети |
| `veil_network_reachability_score` | gauge (0-100) | Сводная оценка достижимости | `< 50` в течение 5 м = сигнал изоляции |

### Состояние DHT

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_dht_store_total` | counter | Обслуженные операции DHT STORE | резкое падение до 0 = изоляция от сети |
| `veil_dht_lookup_total` | counter | Обслуженные запросы DHT FIND_VALUE / FIND_NODE | падение = соседи ушли |
| `veil_storage_evictions_total` | counter | Записи DHT вытеснены по нехватке места | высокий = `max_store_entries` слишком мал |

#### Запасной путь через итеративный DHT (восстановление маршрутов)

Когда узел не может проложить кадр напрямую, он пробует запасной путь:
итеративный поиск в DHT, который ищет свежий транспорт до получателя.
(Итеративный — значит узел идёт по DHT транзит за транзитом, а не полагается на
готовый ответ из кэша.) Эти метрики показывают, как часто запасной путь
срабатывает и удаётся ли он, — раннее свидетельство фрагментации сети:

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_dht_fallback_triggered_total` | counter | Запущены итеративные обращения к DHT после промаха маршрута | рост относительно трафика = прямая маршрутизация деградирует |
| `veil_dht_fallback_resolved_total` | counter | Обращения, заново нашедшие рабочий транспорт | должно идти вровень с `triggered`; разрыв = неразрешимые маршруты |
| `veil_dht_fallback_miss_total` | counter | Обращения, не нашедшие маршрут | рост = маршруты неразрешимы → фрагментация сети |
| `veil_dht_fallback_skipped_backpressure_total` | counter | Обращения подавлены из-за встречного давления (backpressure) | всплески = запасной путь сбрасывается под нагрузкой |
| `veil_dht_fallback_effective_timeout_ms` | gauge (мс) | Текущий адаптивный таймаут запасного пути | нестабильные скачки = перегрузка или нестабильность RTT |

### Почтовый ящик (доставка офлайн-получателям)

Почтовый ящик хранит сообщения для получателей, которые сейчас не в сети, чтобы
передать их, как только те снова подключатся.

> Глубина почтового ящика **в Prometheus не отдаётся**. Единственное место, где
> её видно, — поле `mailbox_entries` в выгрузке состояния через admin HTTP
> (выполните `veil-cli node metrics` или прочитайте точку admin HTTP `/state` как
> JSON или текст). Счётчиков и датчиков `veil_mailbox_*` нет.

| Поле | Источник | Смысл | На что смотреть |
|------|----------|-------|-----------------|
| `mailbox_entries` | выгрузка состояния admin HTTP (JSON/текст), не Prometheus | Конверты, лежащие сейчас в локальном почтовом хранилище | устойчивый рост = получатели остаются не в сети / копится очередь |

### Перегрузка и злоупотребление (congestion / abuse)

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_rate_limit_drops_total` | counter | Входящие кадры отброшены ограничителем частоты по соседу | `> 10/s` в течение 2 м → DoS или неверно настроенный сосед |
| `veil_backpressure_received_total` | counter | Сигналы встречного давления (backpressure) от соседей | нарастание = наша исходящая нагрузка перегружает соседей ниже по потоку |
| `veil_unknown_origin_gossip_rejected_total` | counter | Кадры RouteAnnounce/RouteWithdraw отклонены, так как `via_node_id` не совпал с отправителем на транспорте (подмена via) | устойчиво = вредоносный ретранслятор или расхождение версий |
| `veil_exit_proxy_dest_denied_total` | counter | Цели CONNECT через выходной прокси отклонены (loopback / private / link-local / metadata) | всплеск = зондирование в духе SSRF |
| `veil_socks5_accepts_throttled_total` | counter | Входящие подключения SOCKS5 придержаны (исчерпан `MAX_SOCKS_CONCURRENT`) | устойчиво = перегрузка или злоупотребление |
| `veil_ban_actions_total` | counter | Применены баны, вручную или автоматически | всплеск = идёт атака |
| `veil_session_tx_drops_total` | counter | Исходящие кадры отброшены (очередь передачи переполнена) | `> 50/s` в течение 5 м = перегрузка |
| `veil_session_outbox_drops_total` | counter | Потери из-за переполнения канала исходящих | то же самое |
| `veil_ipc_delivery_drops_total` | counter | Переполнение канала к локальному приложению | приложение не выгребает свой IPC |

### Сквозное шифрование и криптография (E2E / crypto)

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_decrypt_failures_total` | counter | Ошибки расшифровки AEAD на сквозном уровне | устойчиво = расхождение ключей или попытка повтора (replay) |
| `mlkem_key_age_secs` (только admin RPC) | gauge | Возраст локальной пары ключей ML-KEM (время изменения файла) | `> 30 д` → запланируйте ротацию. **Через Prometheus не отдаётся** — запрашивайте через `veil-cli node metrics`. |

### Координаты Vivaldi (оценка сетевого расстояния)

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_vivaldi_prediction_error_ms` | gauge (мс) | Средняя ошибка предсказания Vivaldi | `> 100 мс` → алгоритм не сходится; проверьте синхронизацию времени |
| `veil_vivaldi_coord_x/y/height/error` | gauge | Сырое состояние координат | для справки; для отладки |

### Передача в реальном времени (QUIC realtime)

| Метрика | Тип | Смысл | Оповещать если |
|--------|------|---------|----------|
| `veil_rt_frames_rx_total` | counter | Принятые кадры реального времени | ноль = установка вызова не работает |
| `veil_rt_frames_tx_total` | counter | Отправленные кадры реального времени | расхождение с приёмом → асимметричная потеря |
| `veil_rt_seq_gaps_total` | counter | Кадры реального времени с нарушением порядка или потерянные | высокий = проблема с джиттером (дрожанием задержки) |

## Рекомендуемый набор оповещений

В репозитории лежит готовый для начала [`alerting.yml`](../alerting.yml) —
его можно сразу подключить к Prometheus. Считайте пороги отправной точкой и
подстраивайте под размер вашего парка узлов: значения по умолчанию рассчитаны на
одиночные узлы на обычном железе.

```yaml
groups:
  - name: veil-critical
    rules:
      - alert: NodeDown
        expr: up{job="veil"} == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Veil node {{ $labels.instance }} unreachable"

      - alert: SessionCapacityHigh
        expr: veil_active_sessions / 1000 > 0.8
        for: 5m
        labels: { severity: warning }

      - alert: HighRouteMissRate
        expr: rate(veil_route_miss_total[5m]) > 100
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.instance }} route_miss > 100/s — mesh fragmentation suspected"

      - alert: BackpressureStorm
        expr: rate(veil_rate_limit_drops_total[5m]) > 10
        for: 2m
        labels: { severity: critical }

      - alert: BanStorm
        expr: rate(veil_ban_actions_total[5m]) > 5
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.instance }} banning > 5 peers/s — under attack or misconfig"

      - alert: NetworkIsolated
        expr: veil_network_reachability_score < 50
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.instance }} reachability score < 50 — node may be isolated"

      # NOTE: ML-KEM key-age сейчас не экспозится через Prometheus —
      # только через admin RPC `veil-cli node metrics` snapshot,
      # поле `mlkem_key_age_secs`. Алерт ниже оставлен как шаблон
      # на случай когда метрика появится как Prometheus gauge.
      # - alert: MlKemKeyTooOld
      #   expr: veil_mlkem_key_age_secs > 2592000   # 30 days
      #   for: 1h
      #   labels: { severity: info }
      #   annotations:
      #     summary: "{{ $labels.instance }} ML-KEM key > 30 days — schedule rotation"
```

## Панель Grafana

[Grafana](https://grafana.com) рисует метрики в виде графиков на панели
(dashboard) — это один экран с графиками. Готовая панель поставляется в виде
JSON в `docs/grafana/`. Чтобы загрузить её, откройте интерфейс Grafana → «+» →
Import → Upload JSON. Ключевые секции панели:

1. **Связность** — `active_sessions`, `configured_peers`, датчик достижимости,
   доля неудачных исходящих подключений.
2. **Состояние маршрутизации** — частота route_miss, частота
   discovery_triggered, частота route_recovery, средний RTT, доля попаданий в
   кэш маршрутов (вычисляемая).
3. **DHT** — частота store/lookup, частота вытеснений, число контактов в таблице
   маршрутизации (из самодельной панели `node dht routing | wc -l` или через
   будущую отдачу метрик).
4. **Почтовый ящик** — глубина `mailbox_entries` из выгрузки состояния admin
   HTTP (не Prometheus; через панель с источником данных exec/JSON).
5. **Злоупотребление** — отброшенные ограничителем частоты, действия по банам,
   отклонённый gossip с неизвестным источником, отказы выходного прокси,
   придержанные подключения SOCKS5.
6. **Криптография** — частота ошибок расшифровки, возраст ключа ML-KEM.

## Куда смотреть в первую очередь, когда что-то не так

Идите по списку сверху вниз. Каждый шаг отсекает одну частую причину.

1. **`up{job="veil"}`** — Prometheus вообще достучался до узла? Если нет, узел
   вполне может быть жив, а его точка отдачи метрик привязана не к тому
   интерфейсу. Проверьте `[metrics].listen` и брандмауэр.

2. **`active_sessions`** — число соответствует ожиданиям? Падение обычно значит,
   что вышестоящий сосед упал или кто-то поменял локальную конфигурацию.

3. **`outbound_connect_failures_total / outbound_connect_attempts_total`** —
   отношение этих двух. Если оно держится высоким, узел не достаёт до внешнего
   мира: подозревайте DNS, брандмауэр или недостижимый узел первичного
   подключения.

4. **частота `route_miss_total`** — если высокая, проверьте `node dht routing`,
   насколько заполнены k-бакеты, затем `peers banned` — вдруг вы кого-то
   забанили по ошибке.

5. **частота `ban_actions_total`** — всплеск совпадает с атакой. Запустите
   `veil-cli peers banned`, чтобы увидеть, какие `node_id` банятся и почему.

Полный разбор симптом → диагноз → исправление см. в
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Снимок через CLI (без Prometheus)

Когда нужен быстрый взгляд, а Prometheus не настроен:

```bash
veil-cli node metrics
# Plain-text дамп каждого counter'а/gauge'а — то же содержимое, что и
# /metrics, но human-formatted. Когда [metrics] не задано, печатает
# одну строку-подсказку вместо 35 нулевых counter'ов.
```

Чтобы следить за значимыми событиями вживую, совсем без метрик, читайте лог в реальном времени:

```bash
journalctl -fu veil-node | grep -E "WARN|ERROR|session.banned|route.discovery.miss|recursive.response.relay_dropped"
```
