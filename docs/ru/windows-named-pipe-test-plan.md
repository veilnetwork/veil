# План тестирования: проверка именованного канала на Windows в работе

Именованный канал (named pipe) — это локальный канал межпроцессного
взаимодействия в Windows, её примерный аналог Unix-сокета. Этот план
проверяет, что админ- и IPC-сокеты veil работают поверх такого канала
на реальном Windows-хосте.

> Сборка на Linux-машине разработчика доказывает лишь то, что новый код
> **компилируется** под `x86_64-pc-windows-gnu`. Поведение на уровне
> протокола — привязка, приём, рукопожатие по токену и жизненный цикл
> канала — надо проверять на настоящем Windows. Прогони шаги ниже и
> вернись с выводом. Любой упавший тест или любое сообщение об ошибке,
> не совпадающее с ожидаемым образцом, — это настоящий баг.

## Что нужно заранее

* Windows 10 или 11, любая редакция. API не требует
  привилегированного пользователя.
* `target\debug\veil-cli.exe`, собранный набором инструментов
  `x86_64-pc-windows-msvc`. Кросс-компиляция на Linux
  (`cargo check --target x86_64-pc-windows-gnu`) лишь проверяет типы;
  полная сборка под эти проверки в работе делается на самом Windows
  (`cargo build` из PowerShell в корне репозитория).
* `cargo nextest run` из той же оболочки Windows.

## Тест 1 — config init по умолчанию пишет админ-сокет `pipe://`

На платформах, отличных от Unix, `default_admin_socket_uri()` сейчас
возвращает `"tcp://127.0.0.1:0"`. Этот тест проверяет, что оператор
может **явно включить** `pipe://`. По умолчанию остаётся TCP, поэтому
старые настройки продолжают работать.

```powershell
$tmp = New-TemporaryFile | %{ Remove-Item $_; $_.FullName + ".d" }
mkdir $tmp | Out-Null
cargo run --bin veil-cli -- config init "$tmp\config.toml" --difficulty 1
# Переопределяем на pipe:// для этого теста
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set global.admin_socket "pipe://veil-test-admin"
cargo run --bin veil-cli -- --config "$tmp\config.toml" config get global.admin_socket
```

**Ожидается**: последняя строка печатает `pipe://veil-test-admin`, без
ошибок.

## Тест 2 — `node run --foreground` привязывает именованный канал и пишет спутники

Спутник (sidecar) здесь — это небольшой файл, который узел кладёт рядом
с конфигом, чтобы сообщить, как до него достучаться: например,
`admin.pipe` (имя канала) и `admin.token` (токен доступа).

> **Замечание (Windows):** запуск `node run` в фоне требует поддержки
> демона, которой на Windows пока нет. Используй `--foreground` на
> Windows, чтобы узел остался привязан к текущей оболочке.

```powershell
# В одной оболочке стартуем node в foreground
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run --foreground
```

В другой оболочке проверяем спутники:

```powershell
ls "$tmp"
# Должно показать: admin.pipe, admin.token (никакого admin.port, никакого admin.sock)
Get-Content "$tmp\admin.pipe"
# Должно напечатать: \\.\pipe\veil-test-admin
Get-Content "$tmp\admin.token"
# Должно напечатать: 64-символьную hex-строку
```

Проверяем, что канал действительно привязан:

```powershell
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
```

**Ожидается**: канал появляется в списке. Если вывод пуст —
`bind_named_pipe` молча упал; ищи в stderr узла `IO error`.

## Тест 3 — `veil-cli node show` подключается через канал

Во второй оболочке, пока узел ещё работает:

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Ожидается**: печатает сводку об узле — node_id, role, admin_socket и
так далее. Этот тест прогоняет весь путь целиком:
- `connect_admin_client_any` находит спутник `admin.pipe`
- `connect_named_pipe` читает токен и открывает
  `\\.\pipe\veil-test-admin`
- рукопожатие по токену проходит
- JSON-запрос и ответ ходят туда-обратно поверх канала

## Тест 4 — неправильный токен отвергается

```powershell
# Портим sidecar с token'ом
"00" * 32 | Out-File -Encoding ascii -NoNewline "$tmp\admin.token"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Ожидается**: ошибка в духе `admin protocol: token mismatch`. В stderr
узла должно появиться событие "token mismatch" или
"admin.accept_rejected". **Узел не должен падать** — `accept_rejected`
это мягкий сбой в рамках одного соединения.

## Тест 5 — узел завершается чисто

В оболочке узла нажми `Ctrl+C`. Затем проверь, что спутники прибраны:

```powershell
ls "$tmp"
# admin.pipe и admin.token должны оба исчезнуть.
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
# Pipe должен быть unbound.
```

## Тест 6 — IPC поверх именованного канала (то же, что тесты 1-5, но для IPC)

IPC (межпроцессное взаимодействие) — это канал, по которому локальное
приложение общается с узлом, отдельный от админ-сокета.

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.enabled true
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.socket_uri "pipe://veil-test-ipc"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run
```

В другой оболочке проверяем спутники и связь по IPC через
Python-помощник:

```powershell
ls "$tmp"
# Должно включать ipc.pipe + ipc.token.
python .\examples\ovl_proto.py --help
# (У нас пока нет Python NamedPipe хелпера — Step 8 в TASKS.md.
# Пока что просто проверяем, что sidecar'ы есть и node логирует
# `ipc.start`.)
```

## Тест 7 — полный nextest sweep на Windows

```powershell
cargo nextest run --workspace
```

**Ожидается**: 1363+ passed, 14+ skipped (давние медленные тесты
симуляции), 0 failures. В частности, должны пройти
`node::local_transport::tests::*` — они кросс-платформенные (кодек
токена и круговой проход через файл порта).

Если что-то упало — присылай вывод.

## Что прислать обратно

* Тест 1: принял ли `config set` значение `pipe://`?
* Тест 2: содержимое `admin.pipe` и длину `admin.token`. Показывает ли
  `Get-ChildItem \\.\pipe\` запись `veil-test-admin`?
* Тест 3: вывод `node show` или ошибку.
* Тест 4: чисто ли упала попытка с неправильным токеном и выжил ли
  узел?
* Тест 5: прибраны ли спутники при завершении?
* Тест 6: `ls` каталога `$tmp` и любые строки журнала по IPC.
* Тест 7: итоговую строку nextest и любые упавшие тесты с их stderr.
