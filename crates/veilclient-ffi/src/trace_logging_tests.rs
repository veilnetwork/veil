//! Logging initialization is process-global. Each case runs in a fresh test
//! subprocess so embedded-node tests cannot initialize the bridge for it.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

struct HostLogger;
static HOST_LOGGER: HostLogger = HostLogger;
static HOST_RECORDS: AtomicUsize = AtomicUsize::new(0);

impl log::Log for HostLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }
    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            HOST_RECORDS.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn flush(&self) {}
}

#[test]
fn client_only_trace_keeps_its_diagnostics() {
    const CHILD: &str = "VEIL_FFI_TRACE_LOG_TEST_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        // No embedded node or runtime has been created in this process.
        crate::veil_debug_set_rt_trace(0);
        assert_eq!(log::max_level(), log::LevelFilter::Off);
        if mode == "host" {
            log::set_logger(&HOST_LOGGER).unwrap();
            log::set_max_level(log::LevelFilter::Warn);
        }
        crate::veil_debug_set_rt_trace(1);
        assert!(veil_session::rt_trace::rt_trace_enabled());
        if mode == "host" {
            assert_eq!(log::max_level(), log::LevelFilter::Warn);
            log::warn!("host-owned trace logger");
            log::info!("CLIENT_TRACE_CONSOLE_MARKER");
            assert_eq!(HOST_RECORDS.load(Ordering::Relaxed), 1);
        } else {
            assert!(log::log_enabled!(log::Level::Info));
            log::info!("CLIENT_TRACE_CONSOLE_MARKER");
        }
        assert_eq!(crate::veil_debug_flush_console_logs(2000), 0);
        assert_eq!(crate::veil_debug_console_log_dropped(), 0);
        assert_eq!(crate::veil_debug_console_log_write_errors(), 0);
        crate::veil_debug_set_rt_trace(0);
        assert!(!veil_session::rt_trace::rt_trace_enabled());
        eprintln!("CLIENT_TRACE_CASE_{mode}_OK");
        return;
    }

    for mode in ["default", "host"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trace_logging_tests::client_only_trace_keeps_its_diagnostics",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{mode}: {stderr}");
        assert!(stderr.contains(&format!("CLIENT_TRACE_CASE_{mode}_OK")));
        assert_eq!(
            stderr.matches("CLIENT_TRACE_CONSOLE_MARKER").count(),
            usize::from(mode == "default"),
            "{mode}: {stderr}"
        );
    }
}
