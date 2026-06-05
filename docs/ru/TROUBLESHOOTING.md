# Troubleshooting

> Симптом → вероятная причина → fix. Парный документ к
> [OPERATIONS.md](OPERATIONS.md) и [MONITORING.md](MONITORING.md).

## Быстрая триажная сводка

Перед тем как нырять, захватите state:

```bash
veil-cli -c node.toml node show           # version + uptime + counts
veil-cli -c node.toml peers list          # configured peers
veil-cli -c node.toml peers banned        # активные баны
veil-cli -c node.toml sessions list       # установленные сессии
veil-cli -c node.toml node dht routing    # DHT k-bucket'ы
veil-cli -c node.toml node metrics        # снапшот counter'ов
journalctl -u veil-node --since "10 min ago" > /tmp/veil.log
```

Многие симптомы ниже ссылаются на этот вывод.

---

## Узел не стартует / сразу падает

### `compile_error: release build without seeds`
В release-сборке нет seed-записей и не включён ни feature-флаг
`production-seeds`, ни `allow-empty-seeds`. См.
[OPERATIONS.md → Настройка seed-узла](OPERATIONS.md#настройка-seed-узла).
Для testnet-сборок: `cargo build --release --features allow-empty-seeds`.

### `error: identity validation failed: PoW score N < required 24`
Сконфигурированный `[identity]` nonce больше не удовлетворяет difficulty
floor (вероятно, сложность подняли в коде). Re-mine'ите:

```bash
veil-cli config init --force /path/to/config.toml
# или для sovereign identity:
veil-cli identity create --veil-dir /path/to/veil
```

### `error: admin socket already in use`
Предыдущий `veil-cli node run` оставил stale socket-файл. Если ни
один veil-процесс не запущен:

```bash
rm /run/veil/admin.sock
systemctl start veil-node
```

### Узел стартует, потом тихо выходит
Проверьте `journalctl -u veil-node --since "5 min ago"`. Часто:
отсутствует `identity_document.bin` после переноса/восстановления — если
так, восстановите из BIP-39 phrase согласно
[OPERATIONS.md → Потеря identity](OPERATIONS.md#потеря-identity--восстановление-из-bip-39).

---

## Peer'ы не соединяются

### `WARN peer.connect.failure ... Connection refused`
Remote endpoint не слушает, или firewall блокирует. Проверьте с
dialing-узла:

```bash
nc -vz <remote_host> <remote_port>
# Connection refused → service down или firewall reset
# Connection timeout → firewall drop или нет маршрута
```

Если listing-side: `veil-cli node show` должен показывать
`listens_active` > 0; если нет — проверьте лог-строку `listen.start` на
bind-ошибки.

### `INFO session.banned ... node_id=XXXX — banned peer rejected`
Либо вы их забанили, либо они вас. Инспектируйте:

```bash
veil-cli peers banned | grep <node_id_short>
# Если найдено: кто-то явно забанил этот узел, проверьте колонку `reason`.

# Чтобы снять ошибочный ban:
veil-cli peers unban <NODE_ID_HEX>
# NB: баны персистятся в <config-dir>/bans.json — переживают рестарт.
```

Для симметричного бана (ban-script style) нужно сделать `unban` с обеих
сторон, чтобы полностью восстановить линк.

### `WARN peer.nonce_mismatch ... old=XXX new=YYY`
Remote peer пере-замайнил свой identity (например, поднялась difficulty).
Авто-обрабатывается: на reload nonce в `peers[]` конфига авто-обновляется
из handshake'а. Сообщите удалённому оператору, если это неожиданно.

### Peer соединяется, тут же отваливается (handshake.success → session.close)
Вероятно, mismatch OVL1 protocol-версии или превышен session-cap.
Проверьте:

```bash
journalctl -u veil-node | grep -E "handshake|session\.close" | tail -20
# Смотрите "session limit reached" или "version mismatch"
```

Если превышен `max_concurrent`: поднимите `[session].max_concurrent` (default
65536, но ниже в некоторых конфигах).

---

## Сообщения чата / приложений не доставляются

### `RuntimeError: no active OVL1 session to NNNN…`
Это `IPC_SEND_ERR_NO_ROUTE` от локального узла. Routing не нашёл
никакого пути до destination.

**Диагностическая цепочка:**

1. **Прямая сессия до destination?**
   `veil-cli sessions list -v | grep <dst_node_id>` — если есть,
   проблема downstream (забанен, сломан). Если отсутствует, продолжайте.

2. **В DHT k-bucket есть destination?**
   `veil-cli node dht routing | grep <dst_node_id>` — если нет,
   handshake DHT-propagation провалился. В большинстве случаев фиксит
   рестарт.

3. **Забанен?**
   `veil-cli peers banned | grep <dst_node_id>` — если найдено, это
   и есть причина. `peers unban` чтобы снять.

4. **Mesh фрагментирован?** Проверьте, что у двух peer'ов есть общий
   сосед. В ring-топологиях (5 узлов, every-other ban) recursive query
   + reverse-path response chain должен всё равно работать. Проверьте,
   что `veil-cli node show | grep version` соответствует текущему билду.

### `RuntimeError: E2E key for NNNN… not yet cached`
Это `IPC_SEND_ERR_NO_E2E_KEY`. Route известен, но ML-KEM-ключ для
destination ещё не закэширован.

**Причина:** route_cache наполнился через plain RouteAnnounce gossip (без
ML-KEM), или piggy-back RouteResponse так до нас и не дошёл (баг в
pre-467.2f бинарях).

**Fix:** проверьте, что бинарь — post-467.2f (`node show | grep version`).
На retry'е IPC send триггернёт свежий recursive query, который включает
piggy-back RouteResponse с ML-KEM-ключом.

Если retry'и продолжают падать, перезапустите destination-узел — его
`mlkem.key` может быть corrupt; авторегенерируется на следующем старте.

### Сообщения доставляются долго (5+ с)
- Проверьте метрику `route_selection_avg_rtt` — высокий RTT = медленный
  upstream.
- Проверьте counter `decrypt_failures_total` — replays / key drift.
- Проверьте, что не накапливаются retransmits `pending_ack` —
  `veil-cli node metrics | grep ack`.
- Проверьте TTL chat_client'а: default 30 с; снизьте для fast-fail.

### Сообщения дропаются тихо (без ошибки, без доставки)
Кадр может превышать `[session].max_frame_body` — peer дропает oversized
кадры без уведомления. Проверьте, что у sender'а и receiver'а одинаковый
лимит (default 1 MiB). Или сообщение было Chunk'ировано, а sender'ский
peer не договорился о chunking'е — проверьте, что у обеих сторон OVL1
minor ≥ 2.

---

## Баны / abuse

### `INFO session.banned` для peer'а, который должен быть разрешён
Вероятно, auto-banned через `kill_session` (который ставит 30 с temp ban).
Либо подождите 30 с, либо `peers unban` немедленно.

Для sticky-банов проверьте `<config-dir>/bans.json`:

```bash
cat /var/lib/veil/bans.json | jq .
# Редактируйте / удаляйте записи; они перезагружаются на следующем старте узла
```

### Резкий spike метрики ban-storm
- Проверьте `journalctl -u veil-node | grep session.banned` на паттерны
  `node_id`, которые банятся — кластер из одного source-IP?
- Инспектируйте `peers banned` на поток новых записей.
- Подумайте о подстройке rate limits `[abuse]` или per-IP caps.

### Хочется забанить целый /24 subnet
Пока не поддерживается `peers ban` (только per-`node_id`). Workaround:
firewall-правило на уровне хоста (`iptables -A INPUT -s 10.0.0.0/24 -j DROP`).

---

## Странности DHT / routing

### `node dht routing` показывает меньше контактов, чем ожидалось
Pre-Epic-467.2c бинари имели per-bucket rate-limit (max 1 insert в секунду
на bucket), который дропал concurrent handshake adds. Проверьте версию
бинаря: post-467.2c-d это пофикшено.

Если только что рестартанулись и PEX ещё не отработал (PEX обходит каждые
120 с по умолчанию), подождите 2 минуты и проверьте снова.

### `WARN recursive.response.relay_dropped`
Ответ на recursive query не получилось переотправить обратно
originator'у — нет пути через DHT/cache к `reply_to`. Это указывает на
сильную фрагментацию mesh'а; проверьте список banned-pair и убедитесь,
что у originator'а есть хотя бы один общий сосед с responder'ом.

### Loop в логах `recursive.query` (тот же query_id ttl=40 каждые 525 мс)
Originator ретраит, потому что recursive response так и не приехал.
Перекрёстно проверьте логи responder'а на `recursive.response.dropped` —
если он там есть, responder не смог достучаться обратно. Pre-467.2e fix;
убедитесь, что бинарь актуальный.

---

## Mailbox

### `WARN mailbox.quota_reject`
Сработал per-sender rate-limit. Проверьте, кто отправитель:

```bash
journalctl -u veil-node | grep mailbox.quota_reject | tail -20
```

Если это легитимный burst, поднимите `[mailbox].max_per_sender`; если
abuse — забаньте отправителя.

### Mailbox растёт неограниченно
Mailbox pruning должен вытеснять expired (TTL > `mailbox_ttl_secs`,
default 7 д) записи каждую минуту. Если `veil_storage_evictions_total`
не тикает, cleanup task может быть застопорен — проверьте, что
`veil-cli node show | grep uptime` соответствует свежести
metric-counter'а. В крайнем случае рестартаните узел.

### Спящий получатель не просыпается
Проверьте, что wake-up advertisement был эмитнут
(`veil_sleep_advertisements_emitted_total`) И принят
(`veil_sleep_advertisements_accepted_total`). Если эмитнут, но не
принят — gateway / recipient channel сломан.

---

## IPC / chat-клиент

### `chat_client.py: connection refused on app.sock`
Либо узел не запущен, либо в конфиге `[ipc].enabled = false`, либо путь
к сокету отличается от того, что передаёт клиент. Проверьте:

```bash
ls -la /path/to/veil/app.sock
# srwxr-xr-x — сокет существует с правильными правами
```

Если файл есть, но connect refused: узел может быть мёртв; проверьте
`node show`.

### Клиент соединяется, потом соединение сразу закрывается/сбрасывается (без лога демона)
IPC-handshake дропается ещё до завершения, и демон ничего не логирует.
Скорее всего это **cross-user peer-uid mismatch**: демон применяет
peer-uid-гейт на уровне ядра на app-IPC-сокете (`SO_PEERCRED` /
`getpeereid`) и молча `drop()`'ает любое соединение, у которого peer uid
отличается от собственного uid демона — **исключения для root нет**. Тот
же гейт охраняет admin-сокет.

Это бьёт, когда IPC-клиент (`chat_client`, `ogate`, `oproxy`) или
admin-CLI запущен под другим пользователем, чем демон — классика:
запуск их под **root** против демона, работающего под пользователем
`veil`.

**Fix:** запускайте IPC-клиент / admin-CLI под **тем же пользователем**,
что и демон:

```bash
sudo -u veil veil-cli -c node.toml node show
sudo -u veil ogate up
```

**Не** запускайте `ogate` / `oproxy` / admin-CLI под root против
non-root-демона. Для non-root TUN-настройки нужно выдать `CAP_NET_ADMIN`
пользователю демона, а не запускать под root. (На TCP- и Windows
named-pipe-IPC проверка peer-uid — no-op: `uid_matches_local` всегда
true, так что это касается только Unix-socket-транспортов.)

### `chat_client: timeout waiting for reply`
Send мог пройти успешно, но reply потерялся. Проверьте counter'ы sender'а
`veil_pending_ack_*` и `route_miss_total` у recipient'а.

Для pure echo-test debugging запустите `chat_server.py` на том же узле,
что и клиент, чтобы изолировать IPC от сети.

---

## Производительность

### Высокий CPU (процесс `veil-cli`)
- Проверьте `veil_decrypt_failures_total` — высокий указывает на
  replay flood или key drift; путь AEAD-fail дорог.
- Проверьте `veil_active_sessions` — слишком много = scale up.
- Если запущен `lazy_miner`, это ожидаемо во время начального PoW
  (первые ~30 с); должен остановиться потом.

### Высокая память
- `veil_storage_evictions_total` должен расти — если нет, eviction
  застопорен. Проверьте mailbox WAL backend + DHT cap.
- `node dht list | wc -l` — если приближается к `max_store_entries`,
  поднимите cap или примите eviction.

### Высокий network out
Проверьте rate `veil_transport_bytes_tx_total`. Если это relay /
gateway-роль, высокий egress нормален. Если leaf-узел, расследуйте
через `veil-cli sessions list` на неожиданных outbound peer'ов.

---

## Приватность / утечки

### Логи содержат IP'шники peer'ов
INFO-уровень логов по умолчанию включает `transport=tcp://1.2.3.4:5678`
и `source=inbound(peer-N)` для handshake'ов. Для privacy-focused
deployment'ов запускайте с `[global].log_level = "warn"`, чтобы отрезать
INFO-болтовню. Логи WARN/ERROR ссылаются только на `node_id` (уже
непрозрачный).

PII-ревью pending — сейчас workaround = фильтрация по log_level.

### `node show` утёк metrics URL с токеном
`?token=...` query-строки удаляются из отображения `metrics_endpoint`.
Если вы видите токен в текущем выводе, обновитесь до актуального бинаря
(см. `node show | grep version`).

---

## Когда ничего не помогает

1. Захватите state: `node show`, `peers list`, `peers banned`, `sessions list -v`,
   `node dht routing`, `node metrics`, лог журнала за последние 30 мин.
2. Перезапустите узел — это сохраняет баны / DHT-значения / identity, чистит
   transient state.
3. Если по-прежнему сломано, заведите issue с захваченным state'ом и
   релевантным куском лога вокруг момента, когда начались симптомы.
