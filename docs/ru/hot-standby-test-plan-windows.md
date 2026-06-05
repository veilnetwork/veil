# Hot-standby — ручной test plan, multi-host на Windows

Hardware-regression-suite для стадий (b) / (c) / (d) hot-standby —
[hot-standby.md](hot-standby.md). Стадия (a) (in-tree swap-point в
runner'е) верифицирована unit-тестами и не требует Windows-железа.
Стадии (b)/(c)/(d) уже в дереве (2026-04-24), поэтому сценарии ниже —
это живой regression-suite: они прогоняют реальный socket-level
handover между двумя машинами, а не план в ожидании выката.

Почему именно Windows: "multi-host на Windows" важен тут, потому что
(i) у нас end-to-end Windows Service mode, (ii) production-наблюдения
показали middlebox RST на WSS-сессиях от Windows-хостов, который наша
Linux-симуляция не воспроизводит, и (iii) родной Windows TCP stack
вылезает с другим набором partial-write edge case'ов при swap'е,
которые `tokio::io::duplex` на Linux не покрывает.

---

## Топология

Два Windows-хоста:

- **Alice** — `veil-cli service install --config C:\veil\alice.toml`
  + `Start-Service veil-node`. Сконфигурирована с двумя listen-эндпойнтами:

      [[listen]]
      transport = "tls://0.0.0.0:9906"
      advertise = "tls://alice.test:9906"
      tls-cert  = "C:\\veil\\alice-fullchain.pem"
      tls-key   = "C:\\veil\\alice-privkey.pem"

      [[listen]]
      transport = "wss://0.0.0.0:8443/veil"
      advertise = "wss://alice.test:8443/veil"
      tls-cert  = "C:\\veil\\alice-fullchain.pem"
      tls-key   = "C:\\veil\\alice-privkey.pem"

- **Bob** — тот же паттерн; `bob.test` на обоих портах.

Оба хоста знают друг друга через `[[bootstrap_peers]]` — либо вручную
прописаны друг на друга через `tls://`, либо оба указаны на один
сторонний bootstrap seed и gossip сходится сам.

Таблица верхнего уровня `[hot_standby]` с `enabled = true` с обеих
сторон. Ключа `alt_scheme_order` больше нет: alt transport
auto-discover'ится из объявленных каждым пиром `[[listen]]`-URI
(стадия (c.3), `auto_set_alt_uri_from_transports`). Если для ручного
теста нужен конкретный alt, пиньте его прямо в swap-команде через
`node swap-transport --alt-uri ...`.

---

## Сценарий 1 — ручной swap, happy path

**Цель:** убедиться, что handoff стадий (a)+(d) работает end-to-end
на реальном TCP.

1. На Alice запусти долгоживущую chat-сессию до Bob:

       python examples\chat_client.py --to <bob_node_id> --say "hello"

   Оставь Python-клиент в интерактивном режиме.

2. На Alice проверь primary transport:

       veil-cli --config C:\veil\alice.toml sessions list

   Запомни колонку `transport` для сессии Bob — должно быть `tls://`.

3. На Alice запусти admin-команду, симулирующую сигнал деградации
   (стадия (c) драйвит это автоматически через
   `AdminCommand::SwapTransport`; для детерминированного ручного теста
   звоним вручную). И `--peer`, и `--alt-uri` обязательны:

       veil-cli --config C:\veil\alice.toml node swap-transport --peer <bob_node_id> --alt-uri wss://bob.test:8443/veil

4. Проверь логи Alice на:

       session.transport_swapped peer_id=<bob> session preserved across transport handover

   и перезапусти `sessions list` — `transport` для Bob должен теперь
   быть `wss://`. `session_id` обязан **остаться прежним**.

5. В Python-клиенте набери ещё одно сообщение. Оно должно прилететь
   на сторону Bob без видимой задержки и без записи "session reset"
   в логе ни с одной стороны.

**Критерий pass.** `session_id` стабилен между шагами 2 и 4;
post-swap сообщение доставлено без переустановки сессии; никаких
`handshake.*` событий между шагом 3 и шагом 5 ни на одном из хостов.

---

## Сценарий 2 — primary неожиданно умирает

**Цель:** убедиться, что in-tree trigger стадии (c) срабатывает на
real-world failure mode'ах, которые Linux-симуляция воспроизвести не может.

1. Тот же стартовый setup, что в сценарии 1.

2. На Alice заблокируй primary transport Windows Firewall'ом:

       New-NetFirewallRule -DisplayName "veil-hotstandby-test" `
           -Direction Outbound -Action Block `
           -Protocol TCP -RemotePort 9906 -RemoteAddress <bob_ip>

3. Отправь ещё одно сообщение. Runner Alice должен увидеть
   последовательные write-ошибки на TLS-socket'е; стадия (c) их
   считает и драйвит swap на warm WSS probe в пределах примерно
   `swap_on_write_errors × send_cadence` (~1-3 с для chat-клиента
   на 1 Hz и дефолтном пороге в 3 ошибки).

4. Сними firewall-rule и подтверди, что сессия всё ещё на WSS —
   primary не возвращается автоматически (это отдельная политика,
   вне scope здесь).

       Remove-NetFirewallRule -DisplayName "veil-hotstandby-test"

**Критерий pass.** Сообщение, отправленное на шаге 3, доставлено
(возможно, с видимой задержкой); лог `session.transport_swapped` на
обоих хостах; никаких `session.handshake_start` /
`session.idle_timeout` / `peer.reconnect` событий, обрамляющих swap,
ни с одной стороны.

---

## Сценарий 3 — flap damping

**Цель:** убедиться, что `max_swaps_per_minute` ограничивает runaway
swap-loop'ы, когда оба transport'а intermittently плохие.

1. Тот же стартовый setup.

2. Переключай firewall-rule из сценария 2 каждые 5 с (PowerShell-loop)
   на протяжении 2 минут. Это попеременно блокирует и разблокирует primary.

3. Изучи лог: события `session.transport_swapped` должны
   ограничиваться `max_swaps_per_minute` (default 4). После того как
   cap достигнут, runner должен залогировать
   `session.swap_rate_limited` и откладывать дальнейшие swap'ы до
   конца окна.

**Критерий pass.** Счётчик swap'ов в логе остаётся ≤ 4 за rolling
минуту; сессия переживает flap-окно (без re-handshake'а); в окне в 2
минуты *хотя бы какие-то* frame'ы доставлены через тот transport,
который был жив на данный момент.

---

## Сценарий 4 — устойчивость handoff-attach'а к replay

**Цель:** убедиться, что announce `HandoffAttach` на warm-socket'е не
может быть проигран off-path observer'ом для угона сессии. Начиная с
audit cycle-6 (T1) пруф — это уже не статический token: `HandoffAttach`
несёт только голый `session_id`, а receiver отвечает свежим
per-socket challenge'ем (`SessionMsg::HandoffChallenge = 24`, 32 байта
`OsRng`), на который initiator обязан ответить
`SessionMsg::HandoffResponse = 25` — `hmac =
BLAKE3::keyed(tx_key)(session_id || challenge)`, keyed по session-AEAD
`tx_key`. Проигранный attach получает *другой* challenge, на который
он не может ответить без session-ключа.

1. На Bob сними пакеты с primary transport'а во время сценария 1:

       netsh trace start capture=yes tracefile=C:\swap.etl

2. Прогони сценарий 1 до конца; останови трассировку:

       netsh trace stop

3. Открой trace в Microsoft Message Analyzer (или конверти через
   `etl2pcapng` и смотри в Wireshark). Найди handoff-frame'ы на
   warm-socket'е. Announce `HandoffAttach` на warm-socket'е — это
   plaintext (pre-OVL1), но он несёт лишь 32-байтный `session_id`;
   HMAC из `HandoffResponse` зависит от per-socket challenge'а, так
   что ничего на проводе не является переиспользуемым token'ом.

4. С третьего хоста (Eve, спуфающий IP Bob'а) попробуй подключиться
   к WSS-порту Alice, который она объявляет, и проиграть захваченные
   байты `HandoffAttach` (голый `session_id`). Alice отвечает на
   socket Eve *свежим* `HandoffChallenge`; Eve не может предъявить
   подходящий HMAC `HandoffResponse` без session-ключа `tx_key`,
   который никогда не покидал AEAD легитимной primary-сессии.
   Устойчивость держится на session-AEAD-ключах, а **не** на
   приватном ключе identity Bob'а. Alice никогда не привязывает
   socket Eve к `swap_rx`.

**Критерий pass.** Проигранный attach Eve получает challenge, но
никогда не байндится — warm-socket дропается, потому что HMAC
`HandoffResponse` не верифицируется против `rx_key` Alice; легитимная
сессия Alice с Bob не затронута, `session_id` не меняется. (Точные
строки лога/причины — деталь реализации; трактуй описанное как
ожидаемое поведение, а не как буквальные имена событий.)

---

## Отчётность

По каждому сценарию собирай:

- вывод `veil-cli node show` и `sessions list` до и после swap'а;
- полный log span от `session.transport_swapped` на одном хосте до
  следующего доставленного application-frame'а на другом;
- вывод `netsh trace`, обрезанный под окно swap'а.

Кладёшь это под `reports/459-hot-standby-YYYY-MM-DD/scenario-N/` в
operations-repo.

---

## Что Linux умеет покрыть, а что нет

Unit-тесты в
[crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs)
используют `tokio::io::duplex` stream'ы — zero-latency, lossless,
всегда в синхроне. Они доказывают, что *механизм* swap'а работает
изолированно. Real-world failure mode'ы, всплывающие только на
Windows + между двумя машинами:

- **Partial-write'ы, попадающие в swap** — Windows TCP может вернуть
  `WSAEWOULDBLOCK` посередине frame'а на старом transport'е, когда
  runner обрабатывает swap. Linux'овые duplex-stream'ы либо
  завершают, либо нет. Гарантия "между frame'ами" из стадии (a)
  это покрывает, но только hardware-тестирование подтверждает, что
  никакие partial-байты не утекают на новый transport.
- **Firewall + Windows Defender + AV-эвристики**, помечающие swap-трафик
  как подозрительный (быстрое socket open + close + open на тот же
  IP). Это может добавить latency или прямо заблокировать swap, что
  меняет калибровку trigger-порогов.
- **Windows Service mode** — veil работает под LocalSystem'ом,
  другие socket-credentials, чем у user-mode `veil-cli node run`.
  Загрузка TLS trust chain'а и per-user cert store'ы расходятся.

Стадии (b)+(c)+(d) уже в дереве (2026-04-24), поэтому эти сценарии —
постоянный regression-suite: прогонять их перед каждым релизом,
который трогает `node/session/runner.rs` или handshake-путь.
Единственный по-настоящему отложенный пункт — проактивный trigger по RTT.
