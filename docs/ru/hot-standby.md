# Hot-standby: переключение transport'а

Смежно с [adaptive-failover.md](adaptive-failover.md), который оценивает
и переключает **маршруты** (записи `next_hop → dst` в `RouteCache`),
этот документ описывает **transport'ы** на одной уже установленной
сессии: если peer, с которым мы говорим, всё ещё достижим, но socket,
который мы используем, начинает сбоить — TCP RST от middlebox'а,
повреждение TLS record'ов, congestion collapse на QUIC — мы хотим
*сохранить сессию* (тот же `session_id`, те же AEAD-ciphers, те же
согласованные capabilities) и поменять только байтовый pipe под ней.

Альтернатива — свежий OVL1 handshake на другом socket'е — дорогая
(PoW-bound identity exchange, kex, derivation cipher'ов), и она
сжигает pending request ID'ы сессии, peer-aliases и любое неоконченное
rekey-состояние. Hot-standby всего этого избегает.

---

## Статус

Фича выкатывается по стадиям. Таблица ниже отслеживает, что уже в
дереве, а что отложено за version gate.

| Stage | Scope | Status |
|-------|-------|--------|
| **(a) Swap-point в runner'е** | `SessionRunner.swap_rx: Option<Receiver<BoxIoStream>>` + `NextInput::SwapStream(..)` обрабатывается между frame'ами в `run()`, так что `self.stream` атомарно подменяется без касания AEAD-state'а. | в дереве (2026-04-24) |
| **(b) Warm-probe task** | Per-session one-shot `WarmProbe`, который дозванивается до alt-URI и выполняет handoff с challenge-response (T1): `HandoffInit`/`HandoffAck` поверх primary, затем bare `HandoffAttach`-announce + `HandoffChallenge(24)` + `HandoffResponse(25)` на warm socket'е. Запускается оператором через admin-команду `node swap-transport` либо автоматически из (c). | в дереве (2026-04-24) |
| **(c) Trigger-логика** | Последовательные write-ошибки + `rx_stall` (idle_timeout × 2/3 без RX) + `primary_closed` (peer FIN/RST). Все три сходятся в `HotStandbyController::try_auto_trigger` с per-peer flap damping. | в дереве (2026-04-24); см. ограничения ниже |
| **(c.3) Авто-обнаружение peer capabilities** | TLV `ADVERTISED_TRANSPORTS_TLV_TAG=0x0012` в AttachPayload передаёт активные `[[listen]]` URI каждой стороны. Controller автоматически заполняет `alt_uri_for` любым advertised URI, отличающимся от primary. | в дереве (2026-04-24) |
| **(d) Cross-peer handoff protocol** | `SessionMsg::HandoffInit` + `HandoffAck` поверх AEAD-сессии, затем на warm socket'е `HandoffAttach` + `HandoffChallenge(24)` + `HandoffResponse(25)`; `peek_and_dispatch` на каждом входящем socket'е делает `peek` (не consume) pending-записи, отправляет свежий `HandoffChallenge` и привязывает socket к `swap_rx` уже существующего runner'а только после того, как HMAC из `HandoffResponse` проходит проверку. | в дереве (2026-04-24) |

### Стадия (c.2.2) — keepalive-probe timeout

При half-block'е Windows Firewall'ом (исходящий A → B дропается, B → A
ещё течёт) ни `rx_stall`, ни `write_error_threshold` не срабатывают
надёжно. `rx_stall` не срабатывает, потому что собственные keepalive и
frame'ы со стороны B продолжают долетать до A, обновляя `last_rx`.
`write_error_threshold` не срабатывает, потому что Windows TCP молча
буферизует записи A в SNDBUF в течение всех ~30 с retransmission-квоты
прежде чем вернуть ошибку — а к тому моменту TCP на стороне B уже
сдаётся и закрывает socket, отправляя runner A в ветку `primary_closed`.

Fix: трекать ack'и на собственные keepalive A. В OVL1 уже есть
`ControlMsg::KeepaliveAck`; стадия (c.2.2) подключает его к
hot-standby-trigger'у. Flow:

1. Runner отправляет `ControlMsg::Keepalive`; если
   `pending_keepalive_ack_since` равно `None`, записывает текущее
   время. (Сохранение самого старого unacked-timestamp'а даёт самое
   широкое окно для легитимной latency.)
2. Dispatcher peer'а отвечает `ControlMsg::KeepaliveAck` — это уже
   было в протоколе, просто ни на что не влияло.
3. Runner перехватывает `KeepaliveAck` до общего вызова dispatcher'а,
   очищает `pending_keepalive_ack_since` и сбрасывает trigger-fired-флаг.
4. Тик таймера: если `pending_keepalive_ack_since.is_some() && now - t >=
   keepalive_probe_timeout`, вызывается
   `fire_hot_standby_trigger("keepalive_probe_timeout")`. По умолчанию
   `keepalive_probe_timeout = 1 × keepalive_interval`. (Изначально
   зашипано как 2 ×; валидация на двух хостах в Windows LAN показала,
   что TCP станции выдаёт RST за ~25-30 с после firewall-блока, что
   опережало probe 2 × 10 с = 20 с на несколько секунд. 1 × interval
   стреляет probe'ом с комфортным запасом до OS-level RST, так что
   `HandoffInit` всё ещё успевает уехать по живой primary.)

#### Тюнинг для синтетических firewall-block тестов

На LAN с правилом Windows Firewall, инжектирующим outbound-block, TCP
peer'а сдаётся за **~9 секунд** (не 25-30 с, которые мы видим, когда
правило неэффективно из-за DNS-mismatch'а). Чтобы увидеть, как
срабатывает c.2.2 в этом синтетическом сценарии, уменьши
`keepalive_interval_secs`, чтобы probe-deadline попал внутрь окна 9 с:

    [session]
    keepalive_interval_secs = 3
    idle_timeout_secs       = 20

При `keepalive_interval = 3 s` первый keepalive jitter'ит в
[1.5, 4.5]; `probe_timeout` тоже 3 с, так что probe срабатывает
примерно в `T = 4.5 + 3 = 7.5 s`, с комфортным запасом до OS-level
RST на `~9 s`.

В production'е (`keepalive_interval_secs = 30`, default) primary
**не** умирает так быстро — TCP retransmission отрабатывает полную
квоту, давая ~60 с полу-сломанного состояния, в которое probe успевает
выстрелить. Никакого тюнинга не требуется.

`sleep_until` в runner'е теперь учитывает probe-deadline, так что
проверка действительно просыпается. Также пофикшен `keepalive_enabled`
— он теперь считает sub-second интервалы включёнными (раньше
`as_secs() > 0` округлял 50 ms вниз до 0, оставляя probe dormant'ом).

Покрыто unit-тестом `keepalive_probe_timeout_fires_trigger_when_no_ack`:
fixture принимает записи, но не доставляет ни байта (нет ack), runner
стреляет trigger'ом в пределах 2 × keepalive_interval.

### Прежний gap на Windows firewall half-block — закрыт

До c.2.2 runner молча выходил по `NextInput::Closed` без
hot-standby-сигнала; сессия переустанавливалась через полный OVL1
handshake вместо warm-probe handoff'а. `NextInput::Closed` теперь
также логирует `session.primary_closed` и стреляет trigger'ом
последний раз — defence-in-depth, хотя к тому моменту `HandoffInit`
уже не может уехать по мёртвой primary. Keepalive-probe timeout из
c.2.2 стреляет ГОРАЗДО раньше, чем `primary_closed`, так что этот
путь срабатывает только тогда, когда и rx_stall, И keepalive-probe
каким-то образом упустили деградацию (полная network partition на
receive-стороне, где никакие keepalive не доходят).

Swap-point стадии (a) — это контракт, на который опираются остальные
стадии. Его корректность доказывают два unit-теста в
[crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs):

- `swap_redirects_runner_to_new_stream_without_reset` — runner,
  обслуживающий Ping→Pong на duplex A, получает duplex B через
  `swap_tx.send`; следующий Ping на B получает Pong, runner не
  заходит в handshake и не дропает сессию.
- `swap_preserves_aead_counter_across_transports` — тот же flow с
  настоящими экземплярами `SessionCipher`. Если бы runner
  реинициализировал `rx_cipher` при swap'е, второй Ping на B проплыл
  бы мимо `rx_cipher.open()` с counter=2, в то время как runner
  ожидает counter=1, молча дропая frame. 2-секундный timeout теста
  обеспечивает negative case.

---

## Безопасность swap'а — почему "между frame'ами" достаточно

Каждый байт wire-трафика принадлежит ровно одному `FrameHeader + body`.
Runner потребляет frame'ы в two-phase loop'е:

1. `await_next_input` блокируется, пока **одно** из {первый байт
   следующего frame'а, outbox-frame, rpc-request, swap-stream, timer}
   не будет готово.
2. Если выигрывает `Byte(b)`, runner дочитывает остаток header'а через
   `read_exact`, расшифровывает + dispatch'ит body, возвращается в loop.

Результат `SwapStream` может выиграть только на шаге 1. Поэтому swap
происходит, когда wire в чистом состоянии: ни одного байта
in-progress frame'а не было потреблено на старом stream'е. На стороне
записи priority-queue flush в начале каждой итерации уже завершён
прежде, чем входим в `await_next_input`, так что никакой частичной
записи тоже не висит.

**Peer**, разумеется, не видит наш scheduler; он может всё ещё быть
посередине frame'а на старом transport'е, когда наша сторона его
сбрасывает. Поэтому follow-up (d) вводит синхронный handoff protocol с
challenge-response (T1): на warm socket'е отправляется bare
`HandoffAttach { session_id }`, после чего receiver выдаёт свежий
per-socket `HandoffChallenge` (32 байта `OsRng`), а initiator должен
доказать владение session-ключом, ответив `HandoffResponse` с
`hmac = BLAKE3::keyed(tx_key)(session_id || challenge)`. Frame'ы на НОВОМ
transport'е начинают течь только после того, как receiver пересчитает
HMAC через `rx_key` и подтвердит совпадение constant-time-сравнением
(replay'нутый attach получает другой challenge и не может быть отвечен
без session-ключа). Байты, оставшиеся на старом wire после этой точки,
отбрасываются TCP/TLS close'ом с обеих сторон.

---

## Чем это отличается от session resumption

Session resumption (`SESSION_TICKET`) — это *холодный* путь: текущая
сессия уже снесена, client передоzванивается, пропуская PoW/kex
proигрыванием ticket'а. Ciphers и request-id-state всё равно строятся
с нуля; RTT = dial + handshake + 1 RTT.

Hot-standby — это *горячий* путь: сессия никогда не сносится. RTT =
один round-trip `HandoffInit` / `HandoffAck` поверх уже активной
зашифрованной сессии плюс сколько уйдёт у warm probe на то, чтобы
перестать быть idle и начать нести реальные frame'ы. В пределе
(probe держится свежим через L2 / QUIC 0-RTT на тот же advertised
address) RTT swap'а равен нулю поверх connect-latency нового
transport'а.

Оба механизма сосуществуют: hot-standby всегда предпочтительнее;
resumption — fallback на случай, когда сессия реально умерла (оба
transport'а упали одновременно, или peer перезагрузился).

---

## Конфигурация (планируется для стадий b/c)

Предлагаемые ручки в `[session.hot_standby]`:

    [session.hot_standby]
    enabled              = false        # opt-in; per-peer privacy impact
                                        # нулевой, но включение per-peer
                                        # warm probe удваивает количество socket'ов
    alt_scheme_order     = ["quic", "wss", "tls"]
                                        # пробуется после primary в этом порядке
    probe_keepalive_secs = 15           # keepalive cadence для warm probe
    swap_on_write_errors = 3            # consecutive wire-level write-ошибки
                                        # на primary → trigger swap
    swap_on_rtt_multiplier = 4.0        # если keepalive RTT > 4× median → swap
    max_swaps_per_minute = 4            # flap-damping ceiling

Их пока не существует; стадия (b) вводит `enabled` + `alt_scheme_order`;
стадия (c) вводит trigger-пороги.
