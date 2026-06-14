//! Windows Service mode.
//!
//! `veil-cli service install` registers the binary with the Windows
//! Service Control Manager (SCM) so the node starts automatically on
//! boot and logs to the Event Log. `service uninstall` removes the
//! registration. `service run` is the entry point invoked by SCM —
//! operators should not call it directly.
//!
//! On non-Windows platforms all three subcommands return a clear
//! `Unsupported` error; the module is present only to keep the CLI
//! shape uniform across targets (the `Service` subcommand is always
//! parseable, even if the OS rejects it).

use std::path::{Path, PathBuf};

use veil_cfg::{self, ConfigError};

/// Service name as registered with Windows SCM. Must match between
/// `install`, `uninstall`, and the `service_dispatcher::start` call in
/// the service-mode entry.
#[cfg(windows)]
pub(super) const SERVICE_NAME: &str = "VeilNode";

/// Human-readable display name shown in `services.msc`.
#[cfg(windows)]
pub(super) const SERVICE_DISPLAY_NAME: &str = "Veil Node";

/// Description registered with SCM.
#[cfg(windows)]
pub(super) const SERVICE_DESCRIPTION: &str =
    "Veil peer-to-peer network node.  See https://github.com/… for docs.";

// ── Platform-agnostic CLI surface ────────────────────────────────────────────

pub fn install(config_path: Option<&Path>) -> veil_cfg::Result<()> {
    let resolved_config = resolve_config_path(config_path)?;
    #[cfg(windows)]
    {
        windows_impl::install(&resolved_config)
    }
    #[cfg(not(windows))]
    {
        let _ = resolved_config;
        Err(ConfigError::ValidationFailed(
            "Windows Service mode is only available on Windows — \
             use systemd / launchd on Unix."
                .to_owned(),
        ))
    }
}

pub fn uninstall() -> veil_cfg::Result<()> {
    #[cfg(windows)]
    {
        windows_impl::uninstall()
    }
    #[cfg(not(windows))]
    {
        Err(ConfigError::ValidationFailed(
            "Windows Service mode is only available on Windows.".to_owned(),
        ))
    }
}

/// Entry point invoked by the Service Control Manager. On Windows this
/// registers a service-main callback and blocks until SCM signals stop;
/// on other platforms it's an error (operators should use `node run`).
pub fn run() -> veil_cfg::Result<()> {
    #[cfg(windows)]
    {
        windows_impl::run_service_dispatcher()
    }
    #[cfg(not(windows))]
    {
        Err(ConfigError::ValidationFailed(
            "`service run` is invoked by Windows SCM and has no use on Unix — \
             use `node run --foreground` instead."
                .to_owned(),
        ))
    }
}

fn resolve_config_path(explicit: Option<&Path>) -> veil_cfg::Result<PathBuf> {
    match explicit {
        Some(p) => {
            let canon = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
            if !canon.is_file() {
                return Err(ConfigError::ValidationFailed(format!(
                    "config path does not exist: {}",
                    canon.display()
                )));
            }
            Ok(canon)
        }
        None => veil_cfg::locate_config(None),
    }
}

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod windows_impl {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    use super::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};
    use veil_cfg::{self, ConfigError};

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    /// Register the current binary as `VeilNode` with SCM, pointing at
    /// `config_path`. Auto-start on boot, normal error-control.
    pub(super) fn install(config_path: &Path) -> veil_cfg::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&std::ffi::OsStr>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(to_cfg_err)?;

        let binary = std::env::current_exe().map_err(ConfigError::Io)?;

        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: binary,
            launch_arguments: vec![
                OsString::from("--config"),
                config_path.as_os_str().to_os_string(),
                OsString::from("service"),
                OsString::from("run"),
            ],
            dependencies: vec![],
            // LocalSystem by default — operators who want a lower-privileged
            // account should edit the service post-install via `sc config`.
            account_name: None,
            account_password: None,
        };

        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .map_err(to_cfg_err)?;
        service
            .set_description(SERVICE_DESCRIPTION)
            .map_err(to_cfg_err)?;
        Ok(())
    }

    /// Deregister the service. Attempts a graceful stop first; if the
    /// service is stuck in `StartPending` / `StopPending` (e.g. a previous
    /// install left a broken binary that never reported Running), falls
    /// through to `DeleteService` which marks the service for deletion.
    /// The SCM removes the record once the process exits or on next reboot.
    pub(super) fn uninstall() -> veil_cfg::Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&std::ffi::OsStr>, ServiceManagerAccess::CONNECT)
                .map_err(to_cfg_err)?;

        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(to_cfg_err)?;

        let status = service.query_status().map_err(to_cfg_err)?;
        match status.current_state {
            ServiceState::Stopped => {
                // Cleanest path — just delete.
            }
            ServiceState::Running => {
                // Graceful stop + poll for completion (up to 10 s).
                service.stop().map_err(to_cfg_err)?;
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    std::thread::sleep(Duration::from_millis(250));
                    let s = service.query_status().map_err(to_cfg_err)?;
                    if s.current_state == ServiceState::Stopped {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        // Fall through to DeleteService which marks for
                        // removal — better than returning a hard error.
                        eprintln!(
                            "warning: service did not stop within 10 s; marking for deletion \
                             (SCM will remove the record when the process exits or on reboot)"
                        );
                        break;
                    }
                }
            }
            other => {
                // StartPending / StopPending / Paused — service.stop will
                // likely fail with a winapi error. Don't bother trying;
                // DeleteService can still mark the service for removal
                // while it's in a pending state.
                eprintln!(
                    "warning: service is in state {:?}; deleting the record — \
                     if a rogue process is still running, `taskkill /F /IM veil-cli.exe` \
                     then retry uninstall",
                    other,
                );
            }
        }
        service.delete().map_err(to_cfg_err)?;
        Ok(())
    }

    /// Hand over to SCM. Blocks until the service stops.
    pub(super) fn run_service_dispatcher() -> veil_cfg::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(to_cfg_err)
    }

    define_windows_service!(ffi_service_main, service_main);

    /// Invoked by `service_dispatcher::start` once SCM has connected. `args`
    /// here is whatever SCM passes to `StartService` (by default `[name]`);
    /// the launch-arguments set at install time (`--config PATH service run`)
    /// end up in the **process** argv — `std::env::args_os` — not here.
    ///
    /// Because SCM has no way to surface errors before a handler is
    /// registered, the very first thing we do is register + set
    /// `StartPending`. From that point on every exit path MUST flip the
    /// service to `Stopped`, otherwise SCM hangs forever in
    /// Start/Stop-Pending and `sc stop` / `service uninstall` can't recover
    /// (what the operator saw on the first run).
    fn service_main(_args: Vec<OsString>) {
        // 1. Channel so the control handler can signal main loop.
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let event_handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = stop_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        // 2. Register control handler (needed before any set_service_status).
        let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
            Ok(h) => h,
            Err(e) => {
                // Nothing we can do — SCM will timeout this process.
                log_service_error(None, &format!("register control handler: {e}"));
                return;
            }
        };

        // 3. Report StartPending with a generous wait_hint so SCM doesn't
        // kill us while we set things up.
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        });

        // 4. Resolve --config from the *process* CLI args. SCM's `_args` is
        // NOT the command line — it's the `StartService` args vector
        // (usually just `[SERVICE_NAME]`). Launch arguments set at
        // install time end up in `std::env::args_os`.
        let config_path = resolve_config_from_env();
        let config_path = match config_path {
            Some(p) if p.is_file() => p,
            Some(p) => {
                let msg = format!("config path from --config does not exist: {}", p.display());
                log_service_error(Some(&p), &msg);
                let _ = set_stopped(&status_handle, ServiceExitCode::Win32(3));
                return;
            }
            None => {
                let msg = "service process missing `--config PATH` in command-line args \
                           (expected via `ImagePath` set at install time); uninstall and reinstall";
                log_service_error(None, msg);
                let _ = set_stopped(&status_handle, ServiceExitCode::Win32(2));
                return;
            }
        };

        // 5. Build tokio runtime and run the node body. Any error here
        // still flips Stopped at the end of the function.
        let run_result = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => {
                let config_for_run = config_path.clone();
                rt.block_on(async move {
                    // Bridge the blocking mpsc::Receiver to a tokio oneshot
                    // so select! can await it.
                    let (scm_tx, scm_rx) = tokio::sync::oneshot::channel::<()>();
                    std::thread::spawn(move || {
                        let _ = stop_rx.recv();
                        let _ = scm_tx.send(());
                    });

                    // Report Running. Even if this fails we still try to
                    // run — SCM may have killed us already, but there's
                    // nothing cleaner to do.
                    let _ = status_handle.set_service_status(ServiceStatus {
                        service_type: SERVICE_TYPE,
                        current_state: ServiceState::Running,
                        controls_accepted: ServiceControlAccept::STOP
                            | ServiceControlAccept::SHUTDOWN,
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 0,
                        wait_hint: Duration::ZERO,
                        process_id: None,
                    });

                    let external_shutdown = async move {
                        let _ = scm_rx.await;
                    };
                    veil_node_runtime::admin::run_foreground_with_shutdown(
                        &config_for_run,
                        true,
                        external_shutdown,
                    )
                    .await
                })
            }
            Err(e) => Err(veil_node_runtime::NodeError::Io(std::io::Error::other(
                format!("tokio runtime: {e}"),
            ))),
        };

        // 6. Always flip to Stopped so SCM / Stop-Service / uninstall work.
        let exit_code = match &run_result {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(e) => {
                log_service_error(Some(&config_path), &format!("node runtime: {e}"));
                ServiceExitCode::Win32(1)
            }
        };
        let _ = set_stopped(&status_handle, exit_code);
    }

    /// Scan `std::env::args_os` for `--config PATH`. Clap already parsed
    /// this when the process started (into `cli.config`), but we're too
    /// deep in the stack to reach that — reparse the env. Matches both
    /// `--config PATH` and `--config=PATH` for robustness.
    fn resolve_config_from_env() -> Option<PathBuf> {
        let flag = OsString::from("--config");
        let mut it = std::env::args_os();
        while let Some(a) = it.next() {
            if a == flag {
                return it.next().map(PathBuf::from);
            }
            // Handle `--config=PATH`.
            if let Some(rest) = a.to_str().and_then(|s| s.strip_prefix("--config=")) {
                return Some(PathBuf::from(rest));
            }
        }
        None
    }

    /// Best-effort error log: writes to a `service.log` file next to the
    /// config when available, else to the platform's runtime-dir. stderr
    /// is useless here because SCM-launched processes have no console.
    fn log_service_error(config_path: Option<&Path>, msg: &str) {
        use std::io::Write as _;
        let dir = config_path
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(veil_cfg::runtime_veil_dir);
        let _ = std::fs::create_dir_all(&dir);
        let log_path = dir.join("veil-service.log");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "[{ts}] VeilNode service: {msg}");
        }
    }

    /// Small helper so every exit path uses the same shape.
    fn set_stopped(
        handle: &service_control_handler::ServiceStatusHandle,
        exit_code: ServiceExitCode,
    ) -> Result<(), windows_service::Error> {
        handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })
    }

    fn to_cfg_err<E: std::fmt::Display>(err: E) -> ConfigError {
        ConfigError::ValidationFailed(format!("Windows Service: {err}"))
    }
}
