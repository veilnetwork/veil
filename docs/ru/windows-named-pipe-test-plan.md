# Test plan: runtime-проверка NamedPipe на Windows

> Cross-platform код (Linux dev box) проверяет только то, что новый
> код **компилируется** под `x86_64-pc-windows-gnu`. Wire-protocol
> поведение (bind / accept / token handshake / lifecycle pipe'а) надо
> валидировать на реальном Windows-хосте. Прогони шаги ниже и
> вернись с выводом; любой упавший тест — или любое сообщение об
> ошибке, не совпадающее с ожидаемым паттерном — это настоящий баг.

## Prerequisites

* Windows 10/11 (любая редакция; API не требует привилегированного
  пользователя).
* Собранный `target\debug\veil-cli.exe` из toolchain'а
  `x86_64-pc-windows-msvc`. Linux-side cross-compile (`cargo check
  --target x86_64-pc-windows-gnu`) — только для type-checking'а;
  полная сборка под runtime-тесты делается на самом Windows
  (`cargo build` из PowerShell в корне репо).
* `cargo nextest run` из той же Windows-оболочки.

## Тест 1 — config init по умолчанию пишет `pipe://` admin-socket

Сейчас `default_admin_socket_uri()` на не-Unix возвращает
`"tcp://127.0.0.1:0"`. Этот тест проверяет, что оператор может
**явно opt-in'нуться** на `pipe://` — дефолтный путь остаётся TCP
для backward-compat.

```powershell
$tmp = New-TemporaryFile | %{ Remove-Item $_; $_.FullName + ".d" }
mkdir $tmp | Out-Null
cargo run --bin veil-cli -- config init "$tmp\config.toml" --difficulty 1
# Переопределяем на pipe:// для этого теста
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set global.admin_socket "pipe://veil-test-admin"
cargo run --bin veil-cli -- --config "$tmp\config.toml" config get global.admin_socket
```

**Ожидается**: последняя строка печатает `pipe://veil-test-admin`
(без ошибок).

## Тест 2 — `node run --foreground` биндит named pipe и пишет sidecars

> **Замечание (Windows):** background-режим `node run` требует
> daemon-support'а, которого на Windows пока нет. Используй
> `--foreground` на Windows, чтобы node остался привязан к текущей
> оболочке.

```powershell
# В одной оболочке стартуем node в foreground
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run --foreground
```

В другой оболочке проверяем sidecar'ы:

```powershell
ls "$tmp"
# Должно показать: admin.pipe, admin.token (никакого admin.port, никакого admin.sock)
Get-Content "$tmp\admin.pipe"
# Должно напечатать: \\.\pipe\veil-test-admin
Get-Content "$tmp\admin.token"
# Должно напечатать: 64-символьную hex-строку
```

Проверяем, что pipe реально забинден:

```powershell
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
```

**Ожидается**: показывает pipe. Если пусто — `bind_named_pipe`
молча упал, смотри stderr ноды на `IO error`.

## Тест 3 — `veil-cli node show` подключается через pipe

Во второй оболочке, пока node ещё работает:

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Ожидается**: печатает summary node'а (node_id, role, admin_socket
и т. д.). Этот тест прогоняет:
- `connect_admin_client_any` детектит sidecar `admin.pipe`
- `connect_named_pipe` читает token + открывает
  `\\.\pipe\veil-test-admin`
- Token handshake проходит
- JSON request/response работает поверх pipe'а

## Тест 4 — неправильный token отвергается

```powershell
# Портим sidecar с token'ом
"00" * 32 | Out-File -Encoding ascii -NoNewline "$tmp\admin.token"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Ожидается**: ошибка вроде `admin protocol: token mismatch` или
аналогичная. stderr ноды должен залогировать событие "token
mismatch" / "admin.accept_rejected". **Node не должен крашиться** —
`accept_rejected` это per-conn soft failure.

## Тест 5 — node чисто завершается

В оболочке ноды нажми `Ctrl+C`. Затем проверь, что sidecar'ы прибраны:

```powershell
ls "$tmp"
# admin.pipe и admin.token должны оба исчезнуть.
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
# Pipe должен быть unbound.
```

## Тест 6 — IPC поверх NamedPipe (параллельно тестам 1-5, но для IPC)

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.enabled true
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.socket_uri "pipe://veil-test-ipc"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run
```

В другой оболочке — проверяем sidecar'ы и IPC connectivity через
Python-хелпер:

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

**Ожидается**: 1363+ passed, 14+ skipped (pre-existing slow-sim-tests).
0 failures. В частности, `node::local_transport::tests::*` должны
пройти (они cross-platform — token codec, port-file roundtrip).

Если что-то упало — присылай вывод.

## Что прислать обратно

* Тест 1: принял ли `config set` значение `pipe://`?
* Тест 2: содержимое `admin.pipe` + длину `admin.token`. Показывает ли
  `Get-ChildItem \\.\pipe\` запись `veil-test-admin`?
* Тест 3: вывод `node show` (или ошибку).
* Тест 4: чисто ли упала попытка с неправильным token'ом? Выжил ли node?
* Тест 5: убраны ли sidecar'ы при shutdown'е?
* Тест 6: `ls` от `$tmp` и любые IPC log-строки.
* Тест 7: summary-строку nextest и любые failures с их stderr.
