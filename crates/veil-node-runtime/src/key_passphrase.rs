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
        // SAFETY: remove_var is unsafe in newer Rust because mutating the
        // process environment is not thread-safe; we call it during startup
        // before tokio runtime spawns any task, so no other thread reads env.
        unsafe {
            std::env::remove_var(ENV_VAR_NAME);
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
        let raw = std::fs::read_to_string(path).map_err(|e| {
            NodeError::InvalidArgument(format!(
                "failed to read key_passphrase_file {}: {e}",
                path.display()
            ))
        })?;
        // Read first non-empty line, trim whitespace (trailing newline).
        let pass = raw.lines().next().unwrap_or("").trim().to_string();
        if pass.is_empty() {
            return Err(NodeError::InvalidArgument(format!(
                "key_passphrase_file {} is empty or contains only whitespace",
                path.display()
            )));
        }
        // Warn if file permissions are too open (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.mode() & 0o777;
                if mode & 0o077 != 0 {
                    logger.warn(
                        "key_passphrase.file_mode_too_open",
                        format!(
                            "key_passphrase_file {} has mode {:o}; expected 0o600 — \
                             group/other readers can leak the passphrase",
                            path.display(),
                            mode,
                        ),
                    );
                }
            }
        }
        logger.info("key_passphrase.source", format!("file={}", path.display()));
        return Ok(Some(Zeroizing::new(pass)));
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
}
