# Windows NamedPipe runtime test plan

A named pipe is Windows' local IPC channel — its rough equivalent of a
Unix domain socket. This plan checks that veil's admin and IPC sockets
work over one on a real Windows host.

> Building on the Linux dev box only proves the new code **compiles**
> for `x86_64-pc-windows-gnu`. The wire-protocol behaviour — bind,
> accept, the token handshake, and the pipe lifecycle — has to be
> checked on real Windows. Run the steps below and paste the output
> back. Any test that fails, or any error message that doesn't match
> the pattern we expect, is a real bug.

## Prerequisites

* Windows 10 or 11, any edition. The API does not need a privileged
  user.
* A `target\debug\veil-cli.exe` built with the
  `x86_64-pc-windows-msvc` toolchain. The Linux-side cross-compile
  (`cargo check --target x86_64-pc-windows-gnu`) only type-checks the
  code; the full build for these runtime tests has to happen on Windows
  itself (`cargo build` from a PowerShell prompt in the repo root).
* `cargo nextest run`, run from that same Windows shell.

## Test 1 — config init writes a `pipe://` admin socket by default

On non-Unix platforms, `default_admin_socket_uri()` currently returns
`"tcp://127.0.0.1:0"`. This test confirms that an operator can
**explicitly opt in** to `pipe://`. The default stays TCP, so older
setups keep working.

```powershell
$tmp = New-TemporaryFile | %{ Remove-Item $_; $_.FullName + ".d" }
mkdir $tmp | Out-Null
cargo run --bin veil-cli -- config init "$tmp\config.toml" --difficulty 1
# Override to pipe:// for this test
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set global.admin_socket "pipe://veil-test-admin"
cargo run --bin veil-cli -- --config "$tmp\config.toml" config get global.admin_socket
```

**Expected**: the last line prints `pipe://veil-test-admin`, with no
error.

## Test 2 — `node run --foreground` binds the named pipe and writes sidecars

A sidecar here is a small file the node drops next to its config to
advertise how to reach it — for example `admin.pipe` (the pipe name)
and `admin.token` (the auth token).

> **Note (Windows):** running `node run` in the background needs daemon
> support that Windows doesn't have yet. Use `--foreground` on Windows
> so the node stays attached to the current shell.

```powershell
# In one shell, start the node in foreground
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run --foreground
```

In another shell, verify the sidecars:

```powershell
ls "$tmp"
# Should show: admin.pipe, admin.token (no admin.port, no admin.sock)
Get-Content "$tmp\admin.pipe"
# Should print: \\.\pipe\veil-test-admin
Get-Content "$tmp\admin.token"
# Should print: 64-char hex string
```

Verify pipe is actually bound:

```powershell
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
```

**Expected**: the pipe shows up. If the output is empty,
`bind_named_pipe` failed silently — check the node's stderr for an
`IO error`.

## Test 3 — `veil-cli node show` connects via the pipe

In a second shell, while the node is still running:

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Expected**: it prints the node summary — node_id, role, admin_socket,
and so on. This exercises the whole path:
- `connect_admin_client_any` detects the `admin.pipe` sidecar
- `connect_named_pipe` reads the token and opens `\\.\pipe\veil-test-admin`
- the token handshake passes
- a JSON request and response round-trip over the pipe

## Test 4 — wrong token is rejected

```powershell
# Corrupt the token sidecar
"00" * 32 | Out-File -Encoding ascii -NoNewline "$tmp\admin.token"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Expected**: an error along the lines of `admin protocol: token
mismatch`. The node's stderr should log a "token mismatch" or
"admin.accept_rejected" event. **The node must not crash** —
`accept_rejected` is a soft, per-connection failure.

## Test 5 — node shuts down cleanly

In the node's shell, press `Ctrl+C`. Then check that the sidecars were
cleaned up:

```powershell
ls "$tmp"
# admin.pipe and admin.token should both be gone.
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
# Pipe should be unbound.
```

## Test 6 — IPC over NamedPipe (the same as Tests 1-5, but for IPC)

IPC (inter-process communication) is the channel a local app uses to
talk to the node, separate from the admin socket.

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.enabled true
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.socket_uri "pipe://veil-test-ipc"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run
```

In the other shell, check the sidecars and the IPC connection with the
Python helper:

```powershell
ls "$tmp"
# Should include ipc.pipe + ipc.token.
python .\examples\ovl_proto.py --help
# (We don't have a Python NamedPipe helper yet — Step 8 in TASKS.md.
# For now, just verify the sidecars exist and the node logs `ipc.start`.)
```

## Test 7 — full nextest sweep on Windows

```powershell
cargo nextest run --workspace
```

**Expected**: 1363+ passed, 14+ skipped (the pre-existing slow sim
tests), and 0 failures. In particular, `node::local_transport::tests::*`
should pass — they're cross-platform (the token codec and the port-file
round-trip).

If anything fails, paste the output back.

## What to send back

* Test 1: did `config set` accept `pipe://`?
* Test 2: the contents of `admin.pipe` and the length of `admin.token`.
  Does `Get-ChildItem \\.\pipe\` list `veil-test-admin`?
* Test 3: the `node show` output, or the error.
* Test 4: did the wrong-token attempt fail cleanly, and did the node
  survive?
* Test 5: were the sidecars cleaned up on shutdown?
* Test 6: the `ls` of `$tmp`, plus any IPC log lines.
* Test 7: the nextest summary line, plus any failures with their
  stderr.
