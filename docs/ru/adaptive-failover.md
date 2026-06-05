# Adaptive failover

Когда трафик к peer'у или destination'у начинает падать — физический разрыв
линка, краш промежуточного relay'я, on-path filtering — veil должен
автоматически перестроить маршрут. Три взаимодополняющих механизма
дают это вместе:

1. **Multi-hop route cache** (всегда включён). `RouteCache` держит до
   `MAX_ROUTES_PER_DST = 4` кандидатов `next_hop` на destination,
   ранжированных по композитному score (RTT + hop count + reputation).
   `lookup_all` возвращает отсортированный список; `dispatch_delivery`
   выбирает лучший.

2. **Fast path demotion на session close** (всегда включён).
   Когда session с peer'ом закрывается — clean или abnormal — dispatcher
   немедленно вызывает `RouteCache::demote_via(closed_peer, factor=4.0)`,
   которая домножает score каждого кэшированного маршрута через этого
   peer'а на 4×. Это выталкивает их из ECMP / multi-path band, так что
   альтернативные `next_hop`'ы выигрывают на ближайшем же вызове
   `lookup_all`. Маршруты НЕ удаляются (peer может вернуться); они
   остаются как last-resort fallback, если всё остальное хуже.

   Без этого хука единственным путём score-update был бы следующий цикл
   ROUTE_PROBE (5–120 с адаптивный интервал), поэтому failover занимал
   десятки секунд. С хуком: < 1 RTT.

3. **Multi-path delivery** (opt-in, по умолчанию off). Две настройки в
   `[routing]`:

       multi_path_enabled = true
       redundant_send = true

   С обеими ON latency-чувствительные кадры (`prio ≤ multi_path_min_priority`)
   дублируются по top-2 путям. Receiver дедуплицирует по `content_id`.
   Стоит 2× bandwidth на затронутых приоритетах; даёт p99-устойчивость к
   single-path failure (никакого заметного нарушения при падении одного
   пути).

## Workflow оператора

Посмотреть текущее routing-состояние для destination'а:

```sh
veil-cli node routes <dst_node_id>
```

Header показывает активные multi-path настройки. Тело — primary `next_hop`
плюс альтернативы (отмечены `(alt)`). После закрытия session'а alt'ы
получат score ниже, чем у demoted-by-4 primary, в течение миллисекунд.

## Когда включать multi-path

По умолчанию OFF — потому что удваивает bandwidth на затронутых приоритетах.
Включай когда:

- Deployment bandwidth-rich (LAN / data center).
- p99 latency важнее, чем total cost (интерактивные / real-time приложения).
- В peer mesh есть естественная избыточность (≥3 well-connected core
  peer'а на регион), чтобы top-2 пути были действительно независимыми.

Не имеет смысла на 3-нодовой тестовой сети: redundant-send путь — это
тот же single peer дважды, никакой пользы.

## Verification

```sh
# Активный конфиг виден в header'е routes:
veil-cli node routes
# → [routing config] multi-path: ON (paths=2, prio≤1)  |  redundant-send: ON  |  ecmp_band=0.20

# Углубиться в конкретный destination после разрыва его session'а:
veil-cli node routes 4f2a... | head -10
# Смотри: primary score должен скакнуть в 4× в момент закрытия session'а,
# (alt)-записи становятся эффективным best path'ом.
```
