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

fn main() {
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
