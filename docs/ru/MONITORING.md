# Руководство по мониторингу

> Операционный справочник: за чем смотреть, зачем и когда алертить. Парный
> документ к [OPERATIONS.md](OPERATIONS.md) (deployment) и
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (реагирование на инциденты).

## Настройка exporter'а

Включите Prometheus exporter в `config.toml`:

```toml
[metrics]
listen      = "tcp://127.0.0.1:9090"   # bind URI (scheme required); bind to 0.0.0.0 only behind a firewall
path        = "/metrics"          # default
auth_token  = "abcd1234..."       # optional bearer token; clients send `Authorization: Bearer …`
```

Перезапустите узел, проверьте:

```bash
curl http://127.0.0.1:9090/metrics
# (с токеном)
curl -H "Authorization: Bearer abcd1234..." http://127.0.0.1:9090/metrics
```

Каждая метрика репортится один раз за scrape, без labels кроме неявного
`instance`, который инжектит Prometheus. Все counter'ы — монотонные
`u64`; gauge'и могут быть `f64` (Vivaldi coords) или `usize`.

## Справочник метрик

Категории упорядочены по ops-utility.

### Liveness / capacity

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_active_sessions` | gauge | OVL1 сессии, установленные сейчас | `> 0.8 × max_concurrent` в течение 5 м |
| `veil_configured_peers` | gauge | Число `[[peers]]` записей | резкое падение = аномалия config-reload |
| `veil_inbound_sessions_total` | counter | Кумулятивные inbound handshakes | spike по rate = scan / abuse |
| `veil_outbound_connect_attempts_total` | counter | Кумулятивные outbound dial-попытки | spike по rate = peer churn / нестабильность сети |
| `veil_outbound_connect_failures_total` | counter | Failed outbound dials | failure-ratio > 50 % за 10 м = upstream peer лёг |
| `veil_session_handshake_failures_total` | counter | Inbound handshake-ошибки (auth / cipher / proto) | spike по rate = scanner или version-skew |

### Routing (самая просматриваемая секция)

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_route_miss_total` | counter | DELIVERY-кадры без route к dst | `> 100/s` в течение 5 м → фрагментация mesh'а; проверьте DHT |
| `veil_discovery_triggered_total` | counter | Запущен reactive route discovery (RecursiveQuery) | резкий spike коррелирует со spike'ом route_miss |
| `veil_route_recovery_total` | counter | Успешные re-route'ы после смерти primary hop | высокий = нестабильный upstream peer |
| `veil_route_selection_avg_rtt_ms` | gauge (мс) | Средний RTT выбранного next-hop | растущий тренд = congestion в сети |
| `veil_network_reachability_score` | gauge (0-100) | Композитная метрика reachability | `< 50` в течение 5 м = isolation alarm |

### DHT health

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_dht_store_total` | counter | Обслуженные DHT STORE-операции | резкое падение до 0 = mesh isolation |
| `veil_dht_lookup_total` | counter | Обслуженные DHT FIND_VALUE / FIND_NODE | падение = peer'ы ушли |
| `veil_storage_evictions_total` | counter | DHT-записи вытеснены по capacity | высокий = `max_store_entries` слишком низкий |

#### Iterative-DHT fallback (восстановление маршрутов)

Когда прямой routing промахивается, узел откатывается на итеративный
DHT-lookup, чтобы перерезолвить transport. Эти сигналы отслеживают
фрагментацию mesh'а и здоровье fallback'а:

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_dht_fallback_triggered_total` | counter | Запущены итеративные DHT-fallback'и после route miss | рост относительно трафика = деградация прямого routing'а |
| `veil_dht_fallback_resolved_total` | counter | Fallback'и, перерезолвившие рабочий transport | должно идти вровень с `triggered`; разрыв = нерезолвимые маршруты |
| `veil_dht_fallback_miss_total` | counter | Fallback'и, не нашедшие маршрут | рост = маршруты нерезолвимы → фрагментация mesh'а |
| `veil_dht_fallback_skipped_backpressure_total` | counter | Fallback'и подавлены под backpressure | spike'и = fallback сбрасывается под нагрузкой |
| `veil_dht_fallback_effective_timeout_ms` | gauge (мс) | Текущий адаптивный fallback-timeout | нестабильные скачки = congestion / нестабильность RTT |

### Mailbox (offline-доставка)

> Глубина mailbox'а **не экспозится в Prometheus**. Единственный
> доступный сигнал — поле `mailbox_entries` в admin HTTP state dump
> (`veil-cli node metrics` или admin HTTP `/state` JSON/text).
> Никаких `veil_mailbox_*` counter'ов или gauge'ей нет.

| Поле | Источник | Смысл | На что смотреть |
|------|----------|-------|-----------------|
| `mailbox_entries` | admin HTTP state dump (JSON/text), не Prometheus | Envelope'ы, лежащие сейчас в локальном mailbox-хранилище | устойчивый рост = получатели остаются offline / копится backlog |

### Congestion / abuse

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_rate_limit_drops_total` | counter | Inbound кадры дропнуты per-peer rate limiter'ом | `> 10/s` в течение 2 м → DoS или misconfigured peer |
| `veil_backpressure_received_total` | counter | Backpressure-сигналы от peer'ов | ramp-up = наш outbound congesting downstream |
| `veil_unknown_origin_gossip_rejected_total` | counter | RouteAnnounce/RouteWithdraw-кадры отклонены, т.к. `via_node_id` не совпал с transport-отправителем (via-spoof) | устойчиво = malicious relay или version-skew |
| `veil_exit_proxy_dest_denied_total` | counter | Exit-proxy CONNECT-цели отклонены (loopback / private / link-local / metadata) | spike = SSRF-подобное зондирование |
| `veil_socks5_accepts_throttled_total` | counter | Inbound SOCKS5 accept'ы throttled (saturated `MAX_SOCKS_CONCURRENT`) | устойчиво = overload или abuse |
| `veil_ban_actions_total` | counter | Manual или auto баны применены | spike = под атакой |
| `veil_session_tx_drops_total` | counter | Outbound кадры дропнуты (TX queue full) | `> 50/s` в течение 5 м = overload |
| `veil_session_outbox_drops_total` | counter | Outbox channel saturation drops | аналогично |
| `veil_ipc_delivery_drops_total` | counter | Local-app channel saturation | app не выгребает свой IPC |

### E2E / crypto

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_decrypt_failures_total` | counter | E2E AEAD decrypt-ошибки | устойчиво = key drift / replay-попытка |
| `mlkem_key_age_secs` (только admin RPC) | gauge | Возраст локального ML-KEM keypair'а (mtime файла) | `> 30 д` → запланируйте ротацию. **Не экспозится через Prometheus** — запрашивайте через `veil-cli node metrics`. |

### Vivaldi coordinates (оценка сетевой дистанции)

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_vivaldi_prediction_error_ms` | gauge (мс) | Средняя ошибка Vivaldi prediction | `> 100 мс` → алгоритм не сходится; проверьте time-sync |
| `veil_vivaldi_coord_x/y/height/error` | gauge | Сырой coord state | informational; для дебага |

### Real-time (QUIC realtime)

| Метрика | Тип | Смысл | Алертить если |
|--------|------|---------|----------|
| `veil_rt_frames_rx_total` | counter | Получены realtime-кадры | flat = call setup сломан |
| `veil_rt_frames_tx_total` | counter | Отправлены realtime-кадры | расхождение с rx → асимметричная потеря |
| `veil_rt_seq_gaps_total` | counter | Out-of-order / dropped realtime-кадры | высокий = проблема с jitter |

## Рекомендуемый набор алертов

Starter [`alerting.yml`](../alerting.yml) лежит в репо. Подстраивайте
пороги под размер вашего флота; дефолты предполагают single-host узлы
на commodity-железе.

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
        expr: veil_active_sessions / 65536 > 0.8
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

## Grafana dashboard

Reference dashboard JSON лежит в `docs/grafana/`. Импортируется через
Grafana UI → "+" → Import → Upload JSON. Ключевые панели:

1. **Connectivity** — `active_sessions`, `configured_peers`, reachability
   gauge, outbound failure ratio.
2. **Routing health** — route_miss rate, discovery_triggered rate,
   route_recovery rate, средний RTT, route-cache hit ratio (derived).
3. **DHT** — store/lookup rate, evictions rate, contacts в routing
   table (из `node dht routing | wc -l` exec dashboard, или через
   будущий export).
4. **Mailbox** — глубина `mailbox_entries` из admin HTTP state dump
   (не Prometheus; через exec/JSON-datasource панель).
5. **Abuse** — rate-limit drops, ban actions, unknown-origin gossip
   rejects, exit-proxy denials, SOCKS5 accept throttles.
6. **Crypto / E2E** — decrypt failures rate, ML-KEM key age.

## Куда смотреть в первую очередь, когда что-то не так

1. **`up{job="veil"}`** — а Prometheus вообще достучался до узла?
   Если нет — узел может быть жив, но admin/metrics endpoint забинден
   не на тот интерфейс; проверьте `[metrics].listen` и firewall.

2. **`active_sessions`** — соответствует ожиданиям? Падение = upstream
   peer outage или локальное изменение конфига.

3. **`outbound_connect_failures_total / outbound_connect_attempts_total`**
   ratio — устойчиво высокий failure ratio = DNS / firewall / проблема с
   reachability bootstrap-peer'а.

4. **rate `route_miss_total`** — высокий → проверьте `node dht routing`
   для k-bucket fill, потом `peers banned` для непреднамеренных банов.

5. **rate `ban_actions_total`** — spike коррелирует с атакой;
   `veil-cli peers banned` чтобы посмотреть, какие `node_id` банятся
   и почему.

Для конкретного маппинга симптом → диагноз → fix см.
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## CLI snapshot (без Prometheus)

Для разовой инспекции без scraping'а:

```bash
veil-cli node metrics
# Plain-text дамп каждого counter'а/gauge'а — то же содержимое, что и
# /metrics, но human-formatted. Когда [metrics] не задано, печатает
# одну строку-подсказку вместо 35 нулевых counter'ов.
```

Для real-time tail значимых событий без metrics scrape:

```bash
journalctl -fu veil-node | grep -E "WARN|ERROR|session.banned|route.discovery.miss|recursive.response.relay_dropped"
```
