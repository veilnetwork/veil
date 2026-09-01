// jemalloc as global allocator on Linux — glibc malloc fragments badly
// under bursty mixed-size allocation patterns (60 KB frames + many small
// frame metadata + Arc/String churn from session reconnects). On veil
// bootstrap hosts this manifested as ~5-10 MB/min RSS growth that did
// not correspond to live-data growth and would not return to OS even when
// traffic stopped — pure fragmentation overhead. jemalloc's arena +
// dirty-page reuse model handles this workload without ambient retention.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Once a minute, the allocator's own accounting — the leak signal RSS
/// cannot give. `allocated` is live bytes by jemalloc's books: monotone
/// growth under steady load is a REAL leak, no fragmentation
/// false-positives (the reason glibc test builds were rejected as a leak
/// catcher). `resident`/`retained` climbing while `allocated` stays flat
/// is the allocator holding pages — expected, and now visibly distinct.
/// Goes to stderr in the node-logger line shape, so the seeds' log
/// collection picks it up with everything else. Short-lived CLI commands
/// exit before the first tick and never emit.
#[cfg(target_os = "linux")]
fn spawn_memory_stats_reporter() {
    std::thread::Builder::new()
        .name("mem-stats".into())
        .spawn(|| {
            use tikv_jemalloc_ctl::{epoch, stats};
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                // Stats are cached per epoch; advance or read yesterday.
                if epoch::advance().is_err() {
                    continue;
                }
                let (Ok(allocated), Ok(active), Ok(resident), Ok(retained)) = (
                    stats::allocated::read(),
                    stats::active::read(),
                    stats::resident::read(),
                    stats::retained::read(),
                ) else {
                    continue;
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                eprintln!(
                    "[{now}.000] INFO  mem.jemalloc      allocated={allocated}                      active={active} resident={resident} retained={retained}"
                );
            }
        })
        .ok();
}

/// Die quietly when the reader goes away, the way every other Unix tool does.
///
/// Rust sets `SIGPIPE` to `SIG_IGN` before `main`, so a write to a closed pipe
/// comes back as `EPIPE` instead of killing the process — and `println!`
/// panics on a failed write. `veil-cli node dht list | head` therefore ended in
/// a panic and a backtrace instead of ten lines and a prompt, which reads like
/// the node broke when nothing did.
///
/// Restoring the default disposition is the smallest fix that covers every
/// print in the binary; the alternative is auditing several hundred `println!`
/// sites for `BrokenPipe`.
///
/// NOT FOR THE DAEMON. The comment here used to say this was "confined to the
/// CLI entry point", and that a long-lived host must keep Rust's default "or
/// an unrelated socket write would take the whole process down". That is
/// exactly right and it did not hold, because `node run` enters through this
/// same `main`: the seed at 2026-09-01 17:22 was killed by SIGPIPE from a
/// relay closing a socket, and stayed dead, because systemd counts SIGPIPE as
/// a clean exit and `Restart=on-failure` does not fire for it. Fifteen
/// minutes of uptime, no error logged by anyone.
///
/// So the disposition is restored only for the short-lived, printing
/// invocations. A daemon keeps Rust's `SIG_IGN` and gets `EPIPE` as an error
/// value, which is what every socket write in it already handles.
#[cfg(unix)]
fn die_quietly_on_broken_pipe() {
    if runs_the_node() {
        return;
    }
    // SAFETY: called at the top of `main`, before any thread is spawned, and
    // `SIG_DFL` for SIGPIPE is what the process would have had without Rust's
    // pre-main override.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// Whether this invocation is the long-running node rather than a command that
/// prints and exits.
///
/// Read from the raw arguments rather than the parsed ones because the choice
/// has to be made before `main` does anything else, and clap has not run yet.
/// `veil-cli [--config FILE] node run [...]` is the shape; a `FILE` that
/// happens to end in `node` followed by a literal `run` would read as the
/// daemon, and the cost of that is a piped CLI call reporting `EPIPE` instead
/// of dying quietly — the harmless direction of this decision.
#[cfg(unix)]
fn runs_the_node() -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    args.windows(2).any(|w| w[0] == "node" && w[1] == "run")
}

#[cfg(all(unix, test))]
mod sigpipe_disposition_tests {
    /// The predicate, over the raw arguments, so the test drives what `main`
    /// drives rather than a copy of it.
    fn runs_the_node(argv: &[&str]) -> bool {
        argv.windows(2).any(|w| w[0] == "node" && w[1] == "run")
    }

    #[test]
    fn the_daemon_keeps_sigpipe_ignored_and_a_printing_command_does_not() {
        // A seed died of SIGPIPE and stayed dead: systemd counts SIGPIPE as a
        // clean exit, so `Restart=on-failure` never fired. The disposition
        // that killed it exists so `dht list | head` does not panic, which is
        // a want of the printing commands and of nothing else.
        for daemon in [
            ["node", "run"].as_slice(),
            ["--config", "/etc/veil/node.toml", "node", "run"].as_slice(),
            ["node", "run", "--foreground"].as_slice(),
            ["-c", "/x.toml", "node", "run", "--foreground"].as_slice(),
        ] {
            assert!(
                runs_the_node(daemon),
                "{daemon:?} is the daemon and would have taken SIG_DFL"
            );
        }

        for cli in [
            ["node", "show"].as_slice(),
            ["node", "dht", "list"].as_slice(),
            ["peers", "add", "k", "n", "tcp://198.51.100.1:1"].as_slice(),
            ["run"].as_slice(),
            ["node"].as_slice(),
            [].as_slice(),
            // `run` before `node` is not the daemon; order is the whole claim.
            ["run", "node"].as_slice(),
        ] {
            assert!(
                !runs_the_node(cli),
                "{cli:?} would keep SIG_IGN and panic on a closed pipe"
            );
        }
    }
}

fn main() {
    #[cfg(unix)]
    die_quietly_on_broken_pipe();
    #[cfg(target_os = "linux")]
    spawn_memory_stats_reporter();
    // This is a real process entry point: nothing has spawned a thread yet, so
    // rewriting the environment here is sound. Declaring it is what lets the
    // runtime erase the passphrase variable after reading it, so a later
    // fork/exec cannot inherit the secret.
    //
    // An EMBEDDED host does not and must not declare this: by the time it
    // calls in, its own threads are already running, and an environment write
    // racing a `getenv` from any of them is undefined behaviour (audit V-06).
    veil_node_runtime::process_env::allow_env_writes();

    // Initialise the `log` facade so all `log::debug!()` / `log::info!()` /
    // `log::warn!()` / `log::error!()` events across the workspace (and the
    // dependency graph) reach stderr.  Audit batch 2026-05-23: pre-fix no
    // backend was registered, so every call was a silent no-op — diagnostic
    // events like `route.discovery.start` (veil-ipc::handlers::send) and
    // route-cache internals were invisible during incident triage.
    //
    // Operator-controlled via `RUST_LOG`:
    //   * unset  ⇒ default `warn` (only warnings / errors)
    //   * `RUST_LOG=debug`               ⇒ workspace-wide debug
    //   * `RUST_LOG=veil_ipc=debug`   ⇒ just the IPC handler
    //   * `RUST_LOG=info,h2=warn`        ⇒ info workspace-wide,
    //                                     h2 (hyper) downgraded
    //
    // NB: the daemon-side **`NodeLogger`** (in `veil-observability`) is
    // independent — it writes directly through its own sink configured by
    // `[global] log_level` / `log_format` and is not affected by `RUST_LOG`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if let Err(err) = veil_cli::cmd::run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
