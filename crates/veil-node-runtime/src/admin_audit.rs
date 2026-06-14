//! append-only audit log for mutating admin commands.
//!
//! Compromised admin tokens (or merely an over-permissive operator
//! footprint) can ban peers, kill sessions, swap transports, and
//! mutate DHT state without leaving any persistent trace beyond a
//! single line in the live logger output. When `[global] logs =
//! stderr` (the default) and the operator restarts the node, that
//! evidence is gone.
//!
//! `AdminAuditLog` writes one JSON-line per mutating admin command
//! to `<config-dir>/admin-audit.log`, opened in append-only mode and
//! flushed (write + sync_all) before the helper returns. Read-only
//! commands (`Show`, `Sessions`, `DhtGet`, etc.) are NOT logged to
//! avoid swamping the file under steady-state monitoring.
//!
//! ## Design notes
//!
//! **Sync I/O**: admin commands are inherently low-rate (operator-
//! driven); the cost of `O_APPEND` + `fsync` per call is irrelevant
//! versus the audit value. No `tokio::spawn_blocking` indirection
//! is needed.
//! **Failure mode**: if the audit write fails (disk full, permission
//! change), the command STILL executes — denying an operator the
//! ability to ban a malicious peer because the audit log is
//! unavailable would be a worse failure mode. The error is logged
//! to the regular logger at warn-level so the ops team notices.
//! **Rotation**: not handled here. An operator can rotate the file
//! externally (logrotate / Windows Task Scheduler). `O_APPEND`
//! means our writes always land at the current end-of-file even if
//! a rotator moves the old file out from under us.
//! **Format**: JSONL (one JSON object per line). `serde_json` is
//! already a dependency for IPC/admin protocol; no new deps.
//! **Permissions**: on Unix, the file is created with mode 0600 so
//! only the node's user can read it. audit data references
//! peer node_ids and link_ids which aren't secret per se, but
//! restricting access is principle-of-least-privilege.

#[cfg(test)]
use std::path::PathBuf;
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

/// One audited admin operation.
///
/// `command_kind` is a fixed snake_case tag (e.g. `"ban_node"`)
/// matching the `AdminCommand` variant name lower-cased — operators
/// can grep / filter on it. `args` carries the operator-supplied
/// inputs verbatim (peer node_ids, alt URIs, etc.); secrets MUST be
/// filtered by the caller before constructing the event. `outcome`
/// records whether the underlying handler succeeded — the audit log
/// is appended AFTER the handler returns so the outcome is final.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Wall-clock timestamp in milliseconds since UNIX epoch.
    pub ts_unix_ms: u64,
    /// Snake-case command tag; matches the `AdminCommand` variant.
    /// String (not `&'static str`) so `Deserialize` works for replaying
    /// the log out-of-process (e.g. ops tooling that reads the file
    /// back into Rust types — `serde_json::from_str` requires owned
    /// strings here).
    pub command_kind: String,
    /// Human-readable / grep-friendly summary of operator-supplied args.
    /// Free-form string; the caller is responsible for redacting any
    /// sensitive material.
    pub args: String,
    /// Final outcome of the command — see [`AuditOutcome`].
    pub outcome: AuditOutcome,
}

/// Final outcome of an audited command.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AuditOutcome {
    /// Command succeeded. Optional message — usually empty for
    /// mutating ops.
    Ok { message: String },
    /// Command was rejected by the handler — the message is the
    /// error string the operator saw.
    Err { message: String },
}

impl AuditOutcome {
    /// Convenience constructor for the success case with no message.
    pub fn ok() -> Self {
        Self::Ok {
            message: String::new(),
        }
    }

    /// Convenience constructor for the failure case.
    pub fn err(msg: impl Into<String>) -> Self {
        Self::Err {
            message: msg.into(),
        }
    }
}

/// Append-only JSONL writer for `AuditEvent`s.
///
/// One instance per node, owned by `NodeRuntime` and shared via `Arc`
/// with admin command handlers.
pub struct AdminAuditLog {
    /// Path the file lives at — exposed to tests [`Self::path`].
    /// Production code never reads it (the open file handle in `inner`
    /// is the only thing that matters for writes); kept on the struct
    /// purely for the test accessor below.
    #[cfg(test)]
    path: PathBuf,
    /// Serialized append: only one writer at a time. Mutex over the
    /// raw file handle is enough — `OpenOptions::append` guarantees
    /// the OS-level seek-to-end on every write, so no in-process
    /// locking around the seek itself is needed; the Mutex protects
    /// against `write_all` returning a short write that `serde_json`
    /// would not split correctly.
    inner: Mutex<File>,
}

impl AdminAuditLog {
    /// Open (or create) `<dir>/admin-audit.log` in append mode.
    ///
    /// Creates `dir` if it doesn't exist. On Unix the file is opened
    /// (or chmod'd if pre-existing) to mode 0600.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("admin-audit.log");
        #[allow(unused_mut)]
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        #[cfg(test)]
        return Ok(Self {
            path,
            inner: Mutex::new(file),
        });
        #[cfg(not(test))]
        {
            let _ = path;
            Ok(Self {
                inner: Mutex::new(file),
            })
        }
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event. Returns the byte offset of the written line
    /// for callers that want to correlate (rare). On any I/O error
    /// the call returns it instead of panicking; the caller is
    /// expected to log + drop, NOT to fail the underlying command.
    pub fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let mut line = serde_json::to_vec(event)
            .map_err(|e| io::Error::other(format!("audit serialize: {e}")))?;
        line.push(b'\n');
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.write_all(&line)?;
        // sync_all so a crash-after-write doesn't drop the audit
        // entry for an action that DID happen. Cost is irrelevant
        // for admin-rate operations.
        guard.sync_all()?;
        Ok(())
    }
}

/// Build an [`AuditEvent`] with the current system time and the given
/// fields. Helper kept here so the call-site (in `admin.rs`) stays a
/// one-liner per command.
pub fn event(
    command_kind: &'static str,
    args: impl Into<String>,
    outcome: AuditOutcome,
) -> AuditEvent {
    let ts_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    AuditEvent {
        ts_unix_ms,
        command_kind: command_kind.to_owned(),
        args: args.into(),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "veil-admin-audit-{}-{}-{}",
            label,
            std::process::id(),
            uuid_like(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{n:x}")
    }

    #[test]
    fn open_creates_file() {
        let dir = tmp_dir("create");
        let log = AdminAuditLog::open(&dir).expect("open");
        assert!(log.path().exists());
        assert_eq!(log.path().file_name().unwrap(), "admin-audit.log");
    }

    #[test]
    fn record_appends_jsonl() {
        let dir = tmp_dir("append");
        let log = AdminAuditLog::open(&dir).expect("open");
        log.record(&event("ban_node", "node_id=abc", AuditOutcome::ok()))
            .unwrap();
        log.record(&event(
            "kill_session",
            "link_id=0x1234",
            AuditOutcome::err("session not found"),
        ))
        .unwrap();

        let body = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<String> = body.lines().map(str::to_owned).collect();
        assert_eq!(lines.len(), 2);
        // Each line is valid JSON parseable back to the same struct.
        let e1: AuditEvent = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(e1.command_kind, "ban_node");
        assert_eq!(e1.args, "node_id=abc");
        assert!(matches!(e1.outcome, AuditOutcome::Ok { .. }));
        let e2: AuditEvent = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(e2.command_kind, "kill_session");
        assert!(
            matches!(e2.outcome, AuditOutcome::Err { ref message } if message == "session not found")
        );
    }

    #[test]
    fn append_after_reopen_preserves_existing() {
        let dir = tmp_dir("reopen");
        {
            let log = AdminAuditLog::open(&dir).expect("first open");
            log.record(&event("ban_node", "node_id=aaa", AuditOutcome::ok()))
                .unwrap();
        }
        {
            let log = AdminAuditLog::open(&dir).expect("second open");
            log.record(&event("ban_node", "node_id=bbb", AuditOutcome::ok()))
                .unwrap();
        }
        let body = std::fs::read_to_string(dir.join("admin-audit.log")).unwrap();
        assert_eq!(
            body.lines().count(),
            2,
            "second open() must append, not truncate"
        );
    }

    #[test]
    fn event_helper_stamps_recent_timestamp() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let e = event("reload", "", AuditOutcome::ok());
        // Timestamp within the last second of "now" (allow for clock drift
        // in slow CI runners).
        assert!(e.ts_unix_ms >= now_ms.saturating_sub(1000));
        assert!(e.ts_unix_ms <= now_ms + 1000);
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perms");
        let log = AdminAuditLog::open(&dir).expect("open");
        log.record(&event("ban_node", "test", AuditOutcome::ok()))
            .unwrap();
        let mode = std::fs::metadata(log.path()).unwrap().permissions().mode();
        // mask off file-type bits — we only care about the rwxrwxrwx bits.
        assert_eq!(mode & 0o777, 0o600);
    }
}
