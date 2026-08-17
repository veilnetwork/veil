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

fn main() {
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
