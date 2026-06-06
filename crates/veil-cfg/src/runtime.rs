//! Tokio-runtime configuration + factory helpers shared across binaries
//! (veil-cli, ogate, oproxy).
//!
//! Each binary used to ship its own ad-hoc tokio init (veil-cli used
//! `GlobalConfig`, ogate read env vars `OGATE_RUNTIME` / `OGATE_WORKERS`,
//! oproxy hard-coded `#[tokio::main(flavor = "multi_thread",
//! worker_threads = 4)]`).  Audit batch 2026-05-23 consolidates them
//! around a single struct + builder so operators get the same knobs
//! everywhere.

use crate::model::RuntimeFlavor;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Tokio runtime knobs.  Designed to be embedded in any operator-facing
/// TOML config under a `[runtime]` section, or flattened into a larger
/// section (current use: `GlobalConfig`).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// `current_thread` (single-thread executor) or `multi_thread`
    /// (work-stealing pool).  Defaults to multi-thread.
    ///
    /// Accepts both `flavor` and `runtime_flavor` keys on input (the
    /// latter for backward-compat with older `[global]` configs that
    /// used a flat schema).
    #[serde(default, alias = "runtime_flavor")]
    pub flavor: RuntimeFlavor,

    /// `multi_thread` only: worker pool size.  `None` → tokio default
    /// (= num_cpus).  Ignored under `current_thread`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_threads: Option<u16>,

    /// Cap for `spawn_blocking` thread pool.  `None` → tokio default
    /// (= 512).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_blocking_threads: Option<u16>,

    /// Idle timeout (milliseconds) before a worker thread is parked.
    /// `None` → tokio default (= 10 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_keep_alive_ms: Option<u64>,

    /// Prefix label for worker threads (visible in tools like `ps -L`,
    /// `top -H`).  Useful when multiple tokio-using daemons run on the
    /// same host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_name: Option<String>,

    /// Per-thread stack size in bytes.  `None` → tokio default (= 2 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_stack_size: Option<usize>,
}

impl RuntimeConfig {
    /// Merge env-var overrides into a `RuntimeConfig`.  Used by ogate /
    /// oproxy for backward-compatible deployments where existing systemd
    /// units pass tuning through environment.  The env layer ALWAYS wins
    /// over the file when set (operator intent: "I added this var to
    /// override the config").
    ///
    /// Env vars consulted (each optional; absent = leave config field
    /// unchanged):
    ///
    /// * `<PREFIX>_RUNTIME` — `multi_thread` | `current_thread`
    /// * `<PREFIX>_WORKERS` — integer worker count
    /// * `<PREFIX>_MAX_BLOCKING_THREADS` — integer blocking pool cap
    ///
    /// Pass a short uppercase prefix like `OGATE` or `OPROXY`.
    pub fn apply_env_overrides(&mut self, prefix: &str) {
        if let Ok(v) = std::env::var(format!("{prefix}_RUNTIME")) {
            match v.as_str() {
                "current_thread" => self.flavor = RuntimeFlavor::CurrentThread,
                "multi_thread" => self.flavor = RuntimeFlavor::MultiThread,
                _ => {} // ignore garbage so a typo doesn't break the daemon
            }
        }
        if let Ok(v) = std::env::var(format!("{prefix}_WORKERS"))
            && let Ok(n) = v.parse::<u16>()
        {
            self.worker_threads = Some(n);
        }
        if let Ok(v) = std::env::var(format!("{prefix}_MAX_BLOCKING_THREADS"))
            && let Ok(n) = v.parse::<u16>()
        {
            self.max_blocking_threads = Some(n);
        }
    }
}

/// Build a `tokio::runtime::Runtime` from a `RuntimeConfig`.
///
/// Guards against zero values (`worker_threads(0)` panics inside tokio)
/// by treating them as "leave unset" — the validator emits warnings but
/// not all binaries run a validator.
pub fn build_tokio_runtime(cfg: &RuntimeConfig) -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = match cfg.flavor {
        RuntimeFlavor::CurrentThread => tokio::runtime::Builder::new_current_thread(),
        RuntimeFlavor::MultiThread => {
            let mut b = tokio::runtime::Builder::new_multi_thread();
            if let Some(n) = cfg.worker_threads
                && n > 0
            {
                b.worker_threads(n as usize);
            }
            if let Some(n) = cfg.max_blocking_threads
                && n > 0
            {
                b.max_blocking_threads(n as usize);
            }
            if let Some(ms) = cfg.thread_keep_alive_ms {
                b.thread_keep_alive(Duration::from_millis(ms));
            }
            b
        }
    };
    if let Some(sz) = cfg.thread_stack_size {
        builder.thread_stack_size(sz);
    }
    if let Some(ref name) = cfg.thread_name {
        builder.thread_name(name.clone());
    }
    builder.enable_all().build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_build_a_multi_thread_runtime() {
        let cfg = RuntimeConfig::default();
        let rt = build_tokio_runtime(&cfg).expect("default runtime must build");
        rt.block_on(async { /* smoke: enter+exit */ });
    }

    #[test]
    fn current_thread_flavor_works() {
        let cfg = RuntimeConfig {
            flavor: RuntimeFlavor::CurrentThread,
            ..Default::default()
        };
        let rt = build_tokio_runtime(&cfg).expect("current_thread must build");
        rt.block_on(async {});
    }

    #[test]
    fn deserialises_both_flavor_and_runtime_flavor_aliases() {
        let new: RuntimeConfig = toml::from_str(
            r#"
            flavor = "current_thread"
            worker_threads = 2
            "#,
        )
        .unwrap();
        assert_eq!(new.flavor, RuntimeFlavor::CurrentThread);
        assert_eq!(new.worker_threads, Some(2));

        // Legacy alias from GlobalConfig still works.
        let legacy: RuntimeConfig = toml::from_str(
            r#"
            runtime_flavor = "current_thread"
            worker_threads = 4
            "#,
        )
        .unwrap();
        assert_eq!(legacy.flavor, RuntimeFlavor::CurrentThread);
        assert_eq!(legacy.worker_threads, Some(4));
    }

    #[test]
    fn zero_worker_threads_does_not_panic() {
        // Validator should flag this but build_tokio_runtime must not
        // panic if user passes 0.
        let cfg = RuntimeConfig {
            worker_threads: Some(0),
            max_blocking_threads: Some(0),
            ..Default::default()
        };
        let rt = build_tokio_runtime(&cfg).expect("zero values must be ignored, not panic");
        rt.block_on(async {});
    }

    #[test]
    fn env_overrides_apply() {
        // Use a unique prefix per-test to avoid cross-test contamination
        // from leaked vars.
        let prefix = "VEILCFG_TEST_RT";
        unsafe {
            std::env::set_var(format!("{prefix}_RUNTIME"), "current_thread");
            std::env::set_var(format!("{prefix}_WORKERS"), "7");
        }
        let mut cfg = RuntimeConfig::default();
        cfg.apply_env_overrides(prefix);
        assert_eq!(cfg.flavor, RuntimeFlavor::CurrentThread);
        assert_eq!(cfg.worker_threads, Some(7));
        unsafe {
            std::env::remove_var(format!("{prefix}_RUNTIME"));
            std::env::remove_var(format!("{prefix}_WORKERS"));
        }
    }
}
