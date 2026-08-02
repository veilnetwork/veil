//! Resolve the ML-KEM key passphrase from the configured source.
//!
//! Priority cascade (highest-security first):
//!
//!   1. `identity.key_passphrase_prompt = true` → interactive stdin prompt
//!   2. `VEIL_KEY_PASSPHRASE` env var (wiped after read)
//!   3. `identity.key_passphrase_file` → owner-only file
//!   4. `identity.key_passphrase` → inline in config (WARN logged)
//!
//! The resolved passphrase is wrapped in [`Zeroizing<String>`] so its heap
//! contents are wiped when the binding goes out of scope. Caller typically:
//!
//! ```ignore
//! let pass = resolve_key_passphrase(&config, &logger)?;
//! load_or_generate_mlkem_key_encrypted(&path, pass.as_deref().map(|p| p.as_str()))?;
//! // `pass` drops here; String memory zeroed.
//! ```
//!
//! # Threat-model honesty
//!
//! * Source (1) prompt: passphrase never touches disk; only safe path
//!   against backup leak AND local FS reader.
//! * Source (2) env: protects against config leak; `/proc/PID/environ` is
//!   readable by same-uid processes BEFORE the daemon `remove_var`s it.
//! * Source (3) file: protects against config leak if file is on a separate
//!   path with restricted ACL (e.g. systemd `LoadCredential=` → ramfs).
//! * Source (4) inline: zero protection against either leak; documented as
//!   such, WARN at startup.
//!
//! What we don't do (yet): `mlock` against swap-out, `prctl(PR_SET_DUMPABLE,0)`
//! against core-dump leak, or secure-page allocators. Those are separate
//! defence-in-depth efforts.

#[cfg(test)]
use std::io::BufRead;

use zeroize::Zeroizing;

use crate::error::{NodeError, Result};
use veil_cfg::Config;
use veil_observability::NodeLogger;

pub const ENV_VAR_NAME: &str = "VEIL_KEY_PASSPHRASE";

/// Resolve the ML-KEM key passphrase from the highest-priority configured
/// source. Returns `Ok(None)` if no source set (plaintext mlkem.key path).
///
/// On error: I/O failure reading a passphrase file, prompt cancellation, or
/// inconsistent config (none of the security-conscious sources resolved when
/// they were requested). Caller propagates as `NodeError`.
pub fn resolve_key_passphrase(
    config: &Config,
    logger: &NodeLogger,
) -> Result<Option<Zeroizing<String>>> {
    let Some(identity) = config.identity.as_ref() else {
        return Ok(None);
    };

    // 1. Interactive prompt — highest security. Fails closed (no fall-through).
    if identity.key_passphrase_prompt {
        logger.info("key_passphrase.source", "interactive_prompt");
        let raw = rpassword::prompt_password("ML-KEM key passphrase: ")
            .map_err(|e| NodeError::InvalidArgument(format!("passphrase prompt failed: {e}")))?;
        if raw.is_empty() {
            return Err(NodeError::InvalidArgument(
                "empty passphrase entered at prompt".to_string(),
            ));
        }
        return Ok(Some(Zeroizing::new(raw)));
    }

    // 2. Env var. Wipe the env-var slot after read so subsequent fork/exec
    //    doesn't inherit it. Same-uid /proc/PID/environ window is tiny but
    //    nonzero — document as a known caveat (see module-level doc).
    if let Ok(raw) = std::env::var(ENV_VAR_NAME) {
        // Erasing the variable stops a later fork/exec inheriting it — worth
        // having, but not at any price. Mutating the environment is not
        // thread-safe, and the old comment ("before tokio spawns any task")
        // was true of the DAEMON and false of the embedded host: a Flutter app
        // has had threads running since before the library was loaded, and a
        // `getenv` from any of them during the write is undefined behaviour
        // (audit V-06).
        //
        // So it is done only where an entry point has declared the process
        // still single-threaded. Where it has not, the variable stays — the
        // same exposure that existed before the erase was added, which the
        // module header already documents, rather than UB in a host we do not
        // control.
        if crate::process_env::env_writes_allowed() {
            // SAFETY: an entry point called `allow_env_writes`, which only a
            // still-single-threaded one may do.
            unsafe {
                std::env::remove_var(ENV_VAR_NAME);
            }
        } else {
            logger.warn(
                "key_passphrase.env_var_retained",
                format!(
                    "{ENV_VAR_NAME} left in the environment: this process is \
                     embedded and may be multi-threaded, so erasing it is not \
                     safe. A fork/exec from this process would inherit it — \
                     prefer key_passphrase_file or key_passphrase_prompt here."
                ),
            );
        }
        logger.info("key_passphrase.source", format!("env_var={ENV_VAR_NAME}"));
        if raw.is_empty() {
            return Err(NodeError::InvalidArgument(format!(
                "{ENV_VAR_NAME} is set but empty"
            )));
        }
        return Ok(Some(Zeroizing::new(raw)));
    }

    // 3. File path.
    if let Some(path) = &identity.key_passphrase_file {
        let raw = read_passphrase_file(path)?;
        // Read first non-empty line, trim whitespace (trailing newline).
        //
        // `raw` is zeroizing, and the slice below borrows from it rather than
        // building a second plain String — the old code went through
        // `read_to_string` and `to_string`, leaving two un-wiped copies of the
        // passphrase on the heap for the process's lifetime (audit V-11).
        let pass = Zeroizing::new(raw.lines().next().unwrap_or("").trim().to_string());
        if pass.is_empty() {
            return Err(NodeError::InvalidArgument(format!(
                "key_passphrase_file {} is empty or contains only whitespace",
                path.display()
            )));
        }
        logger.info("key_passphrase.source", format!("file={}", path.display()));
        return Ok(Some(pass));
    }

    // 4. Inline config. WARN — least secure.
    if let Some(inline) = &identity.key_passphrase {
        if inline.is_empty() {
            return Ok(None);
        }
        logger.warn(
            "key_passphrase.source",
            "inline_config — passphrase stored alongside the encrypted key file; \
             prefer key_passphrase_file or key_passphrase_prompt for production",
        );
        return Ok(Some(Zeroizing::new(inline.clone())));
    }

    // 5. No source configured → plaintext mlkem.key path (legacy).
    Ok(None)
}

/// Test-only helper: read passphrase from a supplied reader instead of stdin.
/// Mirrors the prompt path but uses any `BufRead` impl, so unit tests can
/// pipe known input. Not exposed outside tests.
#[cfg(test)]
pub fn read_passphrase_from<R: BufRead>(reader: &mut R) -> Result<Zeroizing<String>> {
    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .map_err(|e| NodeError::InvalidArgument(format!("read failed: {e}")))?;
    let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
    // Wipe the intermediate `buf` too (not just `trimmed`).
    let _ = Zeroizing::new(buf);
    Ok(Zeroizing::new(trimmed))
}

/// Read a passphrase file into a buffer that wipes itself, refusing anything
/// that would make the secret readable by someone else.
///
/// The old path called `read_to_string` and then `metadata`, which was wrong
/// three ways (audit V-11):
///
/// * the contents landed in a plain `String` that was never zeroized, and the
///   first line was copied into a second one;
/// * a too-open mode was WARNED about and then read anyway — a world-readable
///   passphrase file is a leak, not a style issue;
/// * `metadata` follows symlinks and was a SEPARATE call from the read, so the
///   thing checked and the thing read were not necessarily the same file.
///
/// Now the open carries `O_NOFOLLOW` and every check runs against `fstat` on
/// that same descriptor, so there is no window to swap the target.
#[cfg(unix)]
fn read_passphrase_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let bad = |msg: String| NodeError::InvalidArgument(msg);

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            bad(format!(
                "failed to open key_passphrase_file {}: {e} (a symlink is \
                 refused on purpose — point the config at the real path)",
                path.display()
            ))
        })?;

    // Everything below inspects the OPEN descriptor, not the path.
    let meta = file.metadata().map_err(|e| {
        bad(format!(
            "failed to stat key_passphrase_file {}: {e}",
            path.display()
        ))
    })?;

    if !meta.is_file() {
        return Err(bad(format!(
            "key_passphrase_file {} is not a regular file",
            path.display()
        )));
    }

    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(bad(format!(
            "key_passphrase_file {} has mode {mode:o}; group or other can read \
             it. Run `chmod 600 {}` and start again.",
            path.display(),
            path.display()
        )));
    }

    // SAFETY: `geteuid` reads process state and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(bad(format!(
            "key_passphrase_file {} is owned by uid {} — expected this process \
             (uid {euid}) or root. A file someone else owns can be replaced \
             under us at any time.",
            path.display(),
            meta.uid()
        )));
    }

    // Bounded: a passphrase file is a line, and an unbounded read of whatever
    // the path happens to point at is its own problem.
    const MAX_PASSPHRASE_FILE_BYTES: u64 = 64 * 1024;
    if meta.len() > MAX_PASSPHRASE_FILE_BYTES {
        return Err(bad(format!(
            "key_passphrase_file {} is {} bytes; expected a single line",
            path.display(),
            meta.len()
        )));
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    file.read_to_end(&mut buf).map_err(|e| {
        bad(format!(
            "failed to read key_passphrase_file {}: {e}",
            path.display()
        ))
    })?;

    let text = std::str::from_utf8(&buf)
        .map_err(|_| bad(format!("key_passphrase_file {} is not UTF-8", path.display())))?;
    Ok(Zeroizing::new(text.to_string()))
}

/// Windows has no mode bits and no `O_NOFOLLOW`; checking an ACL properly is a
/// different piece of work, and pretending otherwise would be worse than
/// saying so. The contents are still read into a zeroizing buffer.
#[cfg(not(unix))]
fn read_passphrase_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let raw = std::fs::read(path).map_err(|e| {
        NodeError::InvalidArgument(format!(
            "failed to read key_passphrase_file {}: {e}",
            path.display()
        ))
    })?;
    let buf = Zeroizing::new(raw);
    let text = std::str::from_utf8(&buf).map_err(|_| {
        NodeError::InvalidArgument(format!(
            "key_passphrase_file {} is not UTF-8",
            path.display()
        ))
    })?;
    Ok(Zeroizing::new(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_passphrase_from_trims_newline() {
        let mut input = Cursor::new(b"secret123\n".to_vec());
        let pass = read_passphrase_from(&mut input).unwrap();
        assert_eq!(pass.as_str(), "secret123");
    }

    #[test]
    fn read_passphrase_from_handles_crlf() {
        let mut input = Cursor::new(b"with-crlf\r\n".to_vec());
        let pass = read_passphrase_from(&mut input).unwrap();
        assert_eq!(pass.as_str(), "with-crlf");
    }

    #[test]
    fn read_passphrase_from_empty_input() {
        let mut input = Cursor::new(b"".to_vec());
        let pass = read_passphrase_from(&mut input).unwrap();
        assert_eq!(pass.as_str(), "");
    }

    /// A passphrase file readable by anyone else must be REFUSED, not warned
    /// about and read anyway, and the file that gets checked must be the file
    /// that gets read (audit V-11).
    #[cfg(unix)]
    #[test]
    fn a_passphrase_file_anyone_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("v11-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pass");
        std::fs::write(&path, b"hunter2\n").unwrap();

        // Owner-only: accepted, and the value comes back intact.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_passphrase_file(&path).unwrap().lines().next(),
            Some("hunter2")
        );

        // Group- or world-readable: refused. The old code logged a warning and
        // used it, which is the leak the warning was describing.
        for mode in [0o640, 0o604, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = read_passphrase_file(&path)
                .err()
                .unwrap_or_else(|| panic!("mode {mode:o} must be refused"));
            let msg = format!("{err}");
            assert!(
                msg.contains("chmod 600"),
                "the error must say how to fix it: {msg}"
            );
        }

        // A symlink is refused even when it points at a well-permissioned file:
        // checking the path and reading the path were two separate operations,
        // so the target could change in between.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            read_passphrase_file(&link).is_err(),
            "O_NOFOLLOW must refuse a symlinked passphrase file"
        );

        // A directory is not a passphrase.
        assert!(read_passphrase_file(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
