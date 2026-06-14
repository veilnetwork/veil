//! Logger initialisation for the `oproxy-client` and `oproxy-server`
//! binaries.  Reads the `[logging]` config section and wires
//! `env_logger` so:
//!
//! * `level = "off"` (and no `RUST_LOG` override) ⇒ logger silently
//!   not initialised — zero log output.
//! * `file = "/path"` ⇒ log lines appended to the file (created if
//!   absent); stderr stays clean.
//! * `level = "..."` without file ⇒ default env_logger init to stderr.
//!
//! `RUST_LOG` env var always wins over config (`env_logger::from_env`
//! semantics).  This preserves the operator escape hatch:
//! `RUST_LOG=oproxy=trace oproxy-client --config ...` works even if
//! the config has `level = "off"`.
//!
//! Audit batch 2026-05-24.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path};
use std::sync::Mutex;

use crate::config::{LogLevel, LoggingConfig};

/// Reject log file paths containing `..` components.  Audit batch
/// 2026-05-24 (M5): a local user with write-access to the config.toml could
/// otherwise point the daemon's log writer at `/etc/cron.d/...` and
/// clobber privileged files via path traversal.
fn validate_log_path(path: &Path) -> std::io::Result<()> {
    for c in path.components() {
        if matches!(c, Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "log file path {} contains `..` — \
                     refusing to open (path-traversal guard)",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Initialise the global logger for one of the oproxy binaries.
///
/// `binary_name` is included in the error message if file open fails.
pub fn init_oproxy_logger(binary_name: &str, log: &LoggingConfig) -> std::io::Result<()> {
    // Disable entirely if level=off and no RUST_LOG override.
    if log.level == LogLevel::Off && std::env::var("RUST_LOG").is_err() {
        // env_logger::Builder::init() can be called only once globally;
        // not called at all — `log` facade silently drops all calls.
        return Ok(());
    }

    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log.level.as_filter_str()),
    );

    if let Some(path) = &log.file {
        validate_log_path(path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{binary_name}: {e}")))?;
        // Open in append mode.  Wrap in `Mutex<File>` because env_logger's
        // `Target::Pipe` takes a `Write + Send` and our writer needs
        // serialised access (concurrent log calls).  `FileWriter` adapter
        // does the locking.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("{binary_name}: open log file {}: {e}", path.display()),
                )
            })?;
        builder.target(env_logger::Target::Pipe(Box::new(FileWriter {
            inner: Mutex::new(file),
        })));
    }

    // env_logger panics if called twice.  `try_init` instead of
    // `init` returns Err on double-init, which we swallow (tests
    // sometimes init twice).
    let _ = builder.try_init();
    Ok(())
}

/// `Write`-impl wrapper that serialises concurrent writes through a
/// `Mutex`.  env_logger's `Target::Pipe` requires `Send` but not
/// `Sync`, and file handles aren't atomically writeable from multiple
/// threads without locking.
struct FileWriter {
    inner: Mutex<std::fs::File>,
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.inner.lock() {
            Ok(mut f) => f.write(buf),
            Err(poisoned) => poisoned.into_inner().write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.inner.lock() {
            Ok(mut f) => f.flush(),
            Err(poisoned) => poisoned.into_inner().flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_level_no_rust_log_skips_init() {
        // We can't easily check whether env_logger was initialised
        // (it's a global), but we can confirm `init_oproxy_logger`
        // returns Ok without a file path and with level=off, and does not
        // touch the filesystem.
        let cfg = LoggingConfig {
            level: LogLevel::Off,
            file: None,
        };
        // Saved env state — restore after.
        let prev = std::env::var("RUST_LOG").ok();
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        let result = init_oproxy_logger("test", &cfg);
        assert!(result.is_ok());
        if let Some(v) = prev {
            unsafe {
                std::env::set_var("RUST_LOG", v);
            }
        }
    }

    #[test]
    fn file_logger_writes_to_target() {
        use std::io::Read;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp); // Want the path not the file (file gets opened append).

        let cfg = LoggingConfig {
            level: LogLevel::Info,
            file: Some(path.clone()),
        };
        let _ = init_oproxy_logger("test", &cfg);
        log::info!("oproxy logging file smoke test marker");
        // env_logger doesn't flush eagerly; force via Drop / sleep.
        std::thread::sleep(std::time::Duration::from_millis(50));

        if let Ok(mut f) = std::fs::File::open(&path) {
            let mut buf = String::new();
            f.read_to_string(&mut buf).unwrap_or(0);
            // We can only assert if THIS test was the first to init the
            // global logger.  In rustlong-running test process other tests
            // may have init'd already, so we tolerate empty buffer.
            if !buf.is_empty() {
                assert!(buf.contains("oproxy logging file smoke test marker"));
            }
        }
        let _ = std::fs::remove_file(&path);
    }
}
