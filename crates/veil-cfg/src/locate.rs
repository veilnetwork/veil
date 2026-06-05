use std::env;
use std::path::{Path, PathBuf};

use super::{ConfigError, FileFormat, Result};

const CONFIG_BASENAME: &str = "config";

/// Resolve the effective config path: if `config_arg` is `Some`, validate and
/// return it; otherwise walk the default search roots (system dir, then user
/// home) and return the first existing `config.{toml,json}`. Returns
/// [`ConfigError::NotFound`] when no file is found.
pub fn locate_config(config_arg: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = config_arg {
        return locate_from_explicit_path(path);
    }

    for root in default_search_roots() {
        if let Some(path) = locate_in_dir(&root)? {
            return Ok(path);
        }
    }

    Err(ConfigError::NotFound)
}

/// Path used by `node config init` when the user passes no explicit `--config`.
/// Prefers the system veil dir (`/etc/veil/…`) when running as root or
/// when the system dir is writable; otherwise falls back to `~/.veil/`.
pub fn default_init_path() -> PathBuf {
    let system_dir = system_veil_dir();
    if use_system_config_path() {
        system_dir.join("config.toml")
    } else {
        home_veil_dir()
            .unwrap_or_else(|_| PathBuf::from(".veil"))
            .join("config.toml")
    }
}

fn locate_from_explicit_path(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }

    if path.is_dir() {
        return locate_in_dir(path)?
            .ok_or_else(|| ConfigError::MissingPath(path.display().to_string()));
    }

    if path.extension().is_some() {
        return Err(ConfigError::MissingPath(path.display().to_string()));
    }

    locate_in_dir(path)?.ok_or_else(|| ConfigError::MissingPath(path.display().to_string()))
}

fn locate_in_dir(dir: &Path) -> Result<Option<PathBuf>> {
    for extension in FileFormat::supported_extensions() {
        let candidate = dir.join(format!("{CONFIG_BASENAME}.{extension}"));
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
    }

    Ok(None)
}

fn default_search_roots() -> Vec<PathBuf> {
    default_search_roots_from(home_veil_dir().ok(), system_veil_dir())
}

fn home_veil_dir() -> Result<PathBuf> {
    detect_home_dir()
        .map(|path| path.join(".veil"))
        .ok_or(ConfigError::HomeDirUnavailable)
}

fn detect_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env::var_os("USERPROFILE").map(PathBuf::from).or_else(|| {
            let drive = env::var_os("HOMEDRIVE")?;
            let path = env::var_os("HOMEPATH")?;
            let mut buf = PathBuf::from(drive);
            buf.push(path);
            Some(buf)
        })
    }

    #[cfg(not(windows))]
    {
        env::var_os("HOME").map(PathBuf::from)
    }
}

fn default_search_roots_from(home_dir: Option<PathBuf>, system_dir: PathBuf) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(home_dir) = home_dir {
        roots.push(home_dir);
    }

    roots.push(system_dir);
    roots
}

#[cfg(target_os = "windows")]
fn system_veil_dir() -> PathBuf {
    env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("veil")
}

#[cfg(target_os = "macos")]
fn system_veil_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/veil")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_veil_dir() -> PathBuf {
    PathBuf::from("/etc/veil")
}

#[cfg(target_os = "windows")]
fn use_system_config_path() -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
fn use_system_config_path() -> bool {
    is_root_user()
}

#[cfg(all(unix, not(target_os = "windows")))]
fn is_root_user() -> bool {
    // SAFETY: `geteuid` is a side-effect-free libc call that does not require valid pointers.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(all(not(unix), not(target_os = "windows")))]
fn is_root_user() -> bool {
    false
}

// ── Runtime directory ────────────────────────────────────────────

/// Derive a sensible default `global.admin_socket` URI.
///
/// `hint` is interpreted as either the full config file path (in which case
/// the socket is placed next to it as `<stem>.sock`) or its parent directory
/// (socket becomes `<dir>/admin.sock`). When running as root on Unix the
/// system-wide path `/var/run/veil/veil.sock` is used unconditionally.
/// On non-Unix platforms the admin backend is TCP-loopback
/// (`tcp://127.0.0.1:0`), matching [`crate::locate::runtime_veil_dir`]
/// precedence rules.
///
/// Callers: `veil config init` writes this into the new config; the admin
/// endpoint resolver also falls back to this when the loaded config has no
/// explicit `admin_socket`, so minimal hand-written configs "just work"
/// without forcing the operator to configure a socket path.
pub fn default_admin_socket_uri(hint: &Path) -> String {
    #[cfg(unix)]
    {
        if is_root_user() {
            return "unix:///var/run/veil/veil.sock".to_owned();
        }
        let socket_path = if hint.is_dir() {
            hint.join("admin.sock")
        } else {
            hint.with_extension("sock")
        };
        // Canonicalise so a daemon that chdir-s after fork still resolves
        // relative inputs against the original CWD. `std::path::absolute`
        // does not require the file to exist.
        let abs = std::path::absolute(&socket_path).unwrap_or(socket_path);
        format!("unix://{}", abs.display())
    }

    #[cfg(not(unix))]
    {
        let _ = hint;
        "tcp://127.0.0.1:0".to_owned()
    }
}

/// Resolve a per-user runtime directory for transient node artefacts —
/// `admin.sock` on Unix, `admin.port` / `admin.token` for TCP-loopback
/// admin, pid-file, etc.
///
/// Precedence (first match wins):
/// 1. `$VEIL_RUNTIME_DIR` — explicit override for ops/tests.
/// 2. Platform default (see below).
/// 3. `$TMPDIR/veil-<uid>` — last-resort fallback.
///
/// Platform defaults:
/// Linux: `$XDG_RUNTIME_DIR/veil` if set, else `/run/user/<uid>/veil`.
/// macOS: `~/Library/Application Support/veil/run`.
/// Windows: `%LOCALAPPDATA%\veil\run` (or `%APPDATA%\veil\run`).
/// Other Unix: `/tmp/veil-<uid>`.
///
/// The directory is **not** created here — that's the caller's job after
/// applying the correct mode (`0o700` on Unix / ACL-owner-only on Windows).
pub fn runtime_veil_dir() -> PathBuf {
    if let Some(explicit) = env::var_os("VEIL_RUNTIME_DIR") {
        return PathBuf::from(explicit);
    }
    runtime_veil_dir_platform_default()
}

#[cfg(target_os = "linux")]
fn runtime_veil_dir_platform_default() -> PathBuf {
    if let Some(xdg) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(xdg).join("veil");
    }
    // SAFETY: `geteuid` is side-effect-free and pointer-free.
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/run/user/{uid}/veil"))
}

#[cfg(target_os = "macos")]
fn runtime_veil_dir_platform_default() -> PathBuf {
    detect_home_dir()
        .map(|home| home.join("Library/Application Support/veil/run"))
        .unwrap_or_else(|| PathBuf::from("/tmp/veil"))
}

#[cfg(target_os = "windows")]
fn runtime_veil_dir_platform_default() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .or_else(|| env::var_os("APPDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var_os("TEMP").unwrap_or_else(|| "C:\\Windows\\Temp".into()))
        })
        .join("veil")
        .join("run")
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn runtime_veil_dir_platform_default() -> PathBuf {
    // SAFETY: `geteuid` is side-effect-free and pointer-free.
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/veil-{uid}"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn runtime_veil_dir_platform_default() -> PathBuf {
    env::temp_dir().join("veil")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_roots_keep_home_before_system() {
        let roots = default_search_roots_from(
            Some(PathBuf::from("/tmp/home/.veil")),
            PathBuf::from("/tmp/system/veil"),
        );

        assert_eq!(
            roots,
            vec![
                PathBuf::from("/tmp/home/.veil"),
                PathBuf::from("/tmp/system/veil")
            ]
        );
    }

    #[test]
    fn search_roots_fall_back_to_system_only() {
        let roots = default_search_roots_from(None, PathBuf::from("/tmp/system/veil"));
        assert_eq!(roots, vec![PathBuf::from("/tmp/system/veil")]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn system_veil_dir_matches_windows_convention() {
        assert!(system_veil_dir().ends_with("veil"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_veil_dir_matches_macos_convention() {
        assert_eq!(
            system_veil_dir(),
            PathBuf::from("/Library/Application Support/veil")
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn system_veil_dir_matches_unix_convention() {
        assert_eq!(system_veil_dir(), PathBuf::from("/etc/veil"));
    }

    // ── runtime_veil_dir ──────────────────────────────────
    //
    // fix: env var mutations ара process-global; cargo
    // test's default parallel execution would race these tests against
    // each other AND against any other test that reads the same vars.
    // А simple process-wide Mutex serialises them deterministically
    // (preferred over а dev-dep on `serial_test` для keeping the
    // dependency footprint small).
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn runtime_dir_respects_explicit_override() {
        let _g = env_test_lock();
        let prev = env::var_os("VEIL_RUNTIME_DIR");
        unsafe {
            env::set_var("VEIL_RUNTIME_DIR", "/custom/runtime");
        }
        assert_eq!(runtime_veil_dir(), PathBuf::from("/custom/runtime"));
        match prev {
            Some(v) => unsafe { env::set_var("VEIL_RUNTIME_DIR", v) },
            None => unsafe { env::remove_var("VEIL_RUNTIME_DIR") },
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn runtime_dir_on_windows_uses_localappdata_veil_run() {
        let _g = env_test_lock();
        let prev = env::var_os("VEIL_RUNTIME_DIR");
        unsafe {
            env::remove_var("VEIL_RUNTIME_DIR");
        }
        let dir = runtime_veil_dir();
        assert!(dir.ends_with("veil\\run"), "got {dir:?}");
        if let Some(v) = prev {
            unsafe {
                env::set_var("VEIL_RUNTIME_DIR", v);
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn runtime_dir_on_linux_prefers_xdg() {
        let _g = env_test_lock();
        let prev_override = env::var_os("VEIL_RUNTIME_DIR");
        let prev_xdg = env::var_os("XDG_RUNTIME_DIR");
        unsafe {
            env::remove_var("VEIL_RUNTIME_DIR");
            env::set_var("XDG_RUNTIME_DIR", "/run/user/42");
        }
        assert_eq!(runtime_veil_dir(), PathBuf::from("/run/user/42/veil"));
        unsafe {
            match prev_xdg {
                Some(v) => env::set_var("XDG_RUNTIME_DIR", v),
                None => env::remove_var("XDG_RUNTIME_DIR"),
            }
            if let Some(v) = prev_override {
                env::set_var("VEIL_RUNTIME_DIR", v);
            }
        }
    }
}
