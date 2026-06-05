# Windows NamedPipe runtime test plan

> Cross-platform code (Linux dev box) only verifies that the new code
> **compiles** for `x86_64-pc-windows-gnu`.  Wire-protocol behaviour
> (bind / accept / token handshake / pipe lifecycle) needs to be
> validated on a real Windows host.  Run the steps below and paste the
> output back; any test that fails — or any error message that doesn't
> match the expected pattern — is a real bug.

## Prerequisites

* Windows 10/11 (any edition; the API doesn't need privileged user).
* Built `target\debug\veil-cli.exe` from an `x86_64-pc-windows-msvc`
  toolchain.  The Linux-side cross-compile (`cargo check
  --target x86_64-pc-windows-gnu`) is for type-checking only — the
  full build for runtime tests must be done on Windows itself
  (`cargo build` from a PowerShell prompt in the repo root).
* `cargo nextest run` from the same Windows shell.

## Test 1 — config init writes a `pipe://` admin socket by default

Currently `default_admin_socket_uri()` on non-Unix returns
`"tcp://127.0.0.1:0"`.  This test verifies that operators can
**explicitly opt in** to `pipe://` — the default path stays TCP for
back-compat.

```powershell
$tmp = New-TemporaryFile | %{ Remove-Item $_; $_.FullName + ".d" }
mkdir $tmp | Out-Null
cargo run --bin veil-cli -- config init "$tmp\config.toml" --difficulty 1
# Override to pipe:// for this test
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set global.admin_socket "pipe://veil-test-admin"
cargo run --bin veil-cli -- --config "$tmp\config.toml" config get global.admin_socket
```

**Expected**: last line prints `pipe://veil-test-admin` (no error).

## Test 2 — `node run --foreground` binds the named pipe + writes sidecars

> **Note (Windows):** background `node run` requires daemon support that
> isn't yet implemented on Windows.  Use `--foreground`
> on Windows so the node stays attached to the current shell.

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

**Expected**: shows the pipe.  If empty, `bind_named_pipe` failed silently —
check the node's stderr for an `IO error`.

## Test 3 — `veil-cli node show` connects via the pipe

In a second shell while the node is still running:

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Expected**: prints node summary (node_id, role, admin_socket etc.).
This exercises:
- `connect_admin_client_any` detects `admin.pipe` sidecar
- `connect_named_pipe` reads token + opens `\\.\pipe\veil-test-admin`
- Token handshake passes
- JSON request/response works over the pipe

## Test 4 — wrong token is rejected

```powershell
# Corrupt the token sidecar
"00" * 32 | Out-File -Encoding ascii -NoNewline "$tmp\admin.token"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node show
```

**Expected**: error like `admin protocol: token mismatch` or similar.
The node's stderr should log a "token mismatch" / "admin.accept_rejected"
event.  **The node must not crash** — `accept_rejected` is a per-conn
soft failure.

## Test 5 — node shuts down cleanly

In the node's shell, `Ctrl+C`.  Then check sidecar cleanup:

```powershell
ls "$tmp"
# admin.pipe and admin.token should both be gone.
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -eq "veil-test-admin" }
# Pipe should be unbound.
```

## Test 6 — IPC over NamedPipe (parallel to Tests 1-5 but for IPC)

```powershell
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.enabled true
cargo run --bin veil-cli -- --config "$tmp\config.toml" config set ipc.socket_uri "pipe://veil-test-ipc"
cargo run --bin veil-cli -- --config "$tmp\config.toml" node run
```

Other shell — verify sidecars and IPC connectivity via the Python helper:

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

**Expected**: 1363+ passed, 14+ skipped (pre-existing slow-sim-tests).
0 failures.  Specifically, `node::local_transport::tests::*` should
pass (they're cross-platform — token codec, port-file roundtrip).

If anything fails, paste the output back.

## What to send back

* Test 1: did `config set` accept `pipe://`?
* Test 2: contents of `admin.pipe` + `admin.token` length.  Does
  `Get-ChildItem \\.\pipe\` show `veil-test-admin`?
* Test 3: `node show` output (or error).
* Test 4: did the wrong-token attempt fail cleanly?  Did the node
  survive?
* Test 5: were sidecars cleaned up on shutdown?
* Test 6: `ls` of `$tmp` and any IPC log lines.
* Test 7: nextest summary line + any failures with their stderr.
