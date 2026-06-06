//! Atomic binary swap.
//!
//! Final stage of the apply path: take a fetched + verified binary
//! blob and a verified manifest, atomically replace the installed
//! binary, persist the new `installed_release_unix`. Crash-safe at
//! every intermediate step — power loss between any two operations
//! leaves either the OLD binary + OLD release_unix OR the NEW
//! binary + NEW release_unix, never a mismatch.
//!
//! # What this slice does NOT do
//!
//! **Does NOT spawn the replacement process or exit.** That's a
//! separate concern — the operator may want to defer the restart
//! to a maintenance window, restart from systemd, or test the
//! new binary out-of-band. Caller decides.
//!
//! **Does NOT touch identity files.** `~/.veil/identity*`
//! sovereign master files, instance state — all untouched. The
//! only files this writes are `install_path` (the binary) and
//! the InstalledVersionStore JSON. Identity outlives every
//! binary swap.
//!
//! # Crash safety
//!
//! Three on-disk operations:
//!
//! 1. Write binary to `<install_path>.tmp`, fsync, set +x.
//! 2. Rename `<install_path>.tmp` → `<install_path>` (atomic on
//!    Linux/macOS same-FS; atomic on Windows via MoveFileEx
//!    MOVEFILE_REPLACE_EXISTING through `std::fs::rename`).
//! 3. `InstalledVersionStore::write` — its own atomic-write
//!    sequence.
//!
//! Power loss (1) but (2): the.tmp file is leaked
//! but the install_path still has the OLD binary; next apply
//! cleanly overwrites the.tmp. Power loss (2) but before
//! (3): the binary is the NEW version but state file still
//! reports the OLD release_unix; on next check, the manifest's
//! release_unix > installed → "available" again, but the apply
//! step's anti-downgrade check would re-pass (sha256 of installed
//! binary already matches manifest), so the operator can re-apply
//! and the state file gets fixed. No silent corruption either way.
//!
//! # Why we recompute SHA-256 even though fetch already verified
//!
//! Defence in depth. The fetch helper verifies the bytes it
//! returned, but bytes flow through several hops in memory before
//! reaching the apply path (caller may have logged, copied
//! buffered). Recomputing here is microseconds and rules out
//! "operator constructed apply call with wrong bytes-vs-manifest
//! pairing" — a class of bug that's hard to catch in code review
//! but trivial to catch with one extra hash.
//!
//! # Linux vs Windows: running-binary semantics
//!
//! On Linux/macOS the kernel holds an open inode for the running
//! process; renaming over the binary unlinks the old inode but
//! keeps the running process alive on it. Subsequent `exec`
//! reads from the NEW binary. This is the "swap and signal"
//! pattern: apply, then send SIGTERM to self → process restarts
//! into the new binary.
//!
//! On Windows, `MoveFileEx(REPLACE_EXISTING)` over a running.exe
//! fails with ERROR_ACCESS_DENIED. Workaround: rename the OLD
//! binary to `<install_path>.old`, write the NEW binary to
//! install_path, then on restart delete the.old. This module
//! implements the simple Linux-style atomic rename; Windows
//! support is a follow-up sub-slice that wraps this primitive
//! with the.old-shuffle dance.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::installed_version::{InstalledVersionError, InstalledVersionStore};
use super::manifest::{BINARY_SHA256_LEN, VerifiedManifest};

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("binary sha256 mismatch — manifest says {expected_hex} got {got_hex}")]
    Sha256Mismatch {
        expected_hex: String,
        got_hex: String,
    },
    #[error(
        "anti-downgrade: manifest release_unix {manifest} <= installed {installed} \
         (apply rejects equal too — operators must monotonically advance timestamp)"
    )]
    AntiDowngrade { manifest: u64, installed: u64 },
    #[error("installed-version state: {0}")]
    InstalledVersion(#[from] InstalledVersionError),
    #[error(
        "platform mismatch: manifest targets `{manifest_target}` but this host is \
         {host_os}/{host_arch} — refusing to install a foreign-platform binary"
    )]
    PlatformMismatch {
        manifest_target: String,
        host_os: &'static str,
        host_arch: &'static str,
    },
    /// cycle-7 (M5): the running binary is older than the manifest's
    /// `min_compatible_version` — applying would skip a mandatory intermediate
    /// migration. Refuse; the operator must update through the intermediate
    /// release first.
    #[error(
        "incompatible update: this binary is v{current} but the update requires \
         v{min_compatible}+ to apply directly (mandatory intermediate migration) \
         — update through the intermediate release first"
    )]
    IncompatibleVersion {
        current: String,
        min_compatible: String,
    },
    /// C-08 hardening: the keyed installed-version store holds a record with NO
    /// mac (legacy, pre-authentication). Auto-adopting it is a downgrade vector
    /// — a local writer who can reach the state file but not the HMAC key can
    /// strip the mac to re-open the anti-downgrade window — so the apply path
    /// refuses it by default. A genuine one-time migration from a pre-C-08
    /// install must be authorized explicitly
    /// (`ApplyOptions::allow_legacy_state_migration`, surfaced as the CLI
    /// `--allow-legacy-state-migration` flag).
    #[error(
        "installed-version state is unauthenticated (legacy, no MAC): refusing \
         automatically, because a stripped MAC can re-open the anti-downgrade \
         window. ONLY if this host has a GENUINE pre-authentication state file, \
         re-run on a trusted host with --allow-legacy-state-migration — and \
         prefer --migrate-min-release-unix <unix> to assert the anti-downgrade \
         floor, because the unauthenticated file's own value is NOT trusted"
    )]
    LegacyStateMigrationRequired,
    /// cycle-7 hardening: the manifest's `min_compatible_version` is present but
    /// is not valid semver. Fail closed rather than silently treating a
    /// malformed constraint as "no constraint".
    #[error(
        "update manifest declares an unparseable min_compatible_version \
         {min_compatible:?} — refusing to apply (cannot verify version compatibility)"
    )]
    MalformedVersionConstraint { min_compatible: String },
}

/// cycle-7 (M5): is `current` (the running binary's version) recent enough to
/// directly apply an update whose manifest requires `min_compatible`? The
/// signed manifest is the real authenticator; `min_compatible_version` is an
/// additional author-set bound that gates against skipping a mandatory
/// migration.
///
/// Parsing policy (fail-closed): an EMPTY / whitespace-only `min_compatible`
/// means "no constraint" (`Ok`). A NON-empty but unparseable `min_compatible`
/// is REJECTED rather than silently ignored — treating a typo'd or tampered
/// bound as "no constraint" would let a manifest skip the very migration the
/// field exists to enforce. `current` is our own `CARGO_PKG_VERSION` (always
/// valid semver in a real build), so a parse failure there is a build bug and
/// is likewise failed closed.
fn min_compatible_satisfied(current: &str, min_compatible: &str) -> Result<(), ApplyError> {
    let min_trimmed = min_compatible.trim();
    if min_trimmed.is_empty() {
        return Ok(());
    }
    let Ok(min) = semver::Version::parse(min_trimmed) else {
        return Err(ApplyError::MalformedVersionConstraint {
            min_compatible: min_compatible.to_string(),
        });
    };
    let Ok(cur) = semver::Version::parse(current.trim()) else {
        return Err(ApplyError::MalformedVersionConstraint {
            min_compatible: min_compatible.to_string(),
        });
    };
    if cur < min {
        return Err(ApplyError::IncompatibleVersion {
            current: current.to_string(),
            min_compatible: min_compatible.to_string(),
        });
    }
    Ok(())
}

/// Tolerant host/manifest platform compatibility check (audit U5).
///
/// `manifest.platform_target` is operator-supplied free text and the codebase
/// uses more than one convention (`"linux-x86_64"`,
/// `"x86_64-unknown-linux-gnu"`), so a strict string compare would falsely
/// reject valid same-platform manifests. We accept ONLY when the target string
/// positively names BOTH this host's OS and CPU arch (in any of the recognized
/// token spellings); a foreign, typo'd, or otherwise unrecognized target is
/// rejected fail-closed (F5). This catches the wrong-binary brick (a Windows
/// binary overwriting a Linux install — and a mistyped target that the old
/// fail-open path let through) without breaking legitimate updates, whose
/// targets always name OS+arch (the release matrix uses full target triples).
fn host_matches_platform_target(target: &str) -> bool {
    let t = target.to_ascii_lowercase();
    let has = |toks: &[&str]| toks.iter().any(|k| t.contains(k));
    const WIN: &[&str] = &["windows", "win32", "win64", "-pc-windows", "msvc", "mingw"];
    const MAC: &[&str] = &["macos", "darwin", "-apple-", "osx", "ios"];
    const LIN: &[&str] = &["linux"];
    const BSD: &[&str] = &["freebsd", "netbsd", "openbsd"];
    const X64: &[&str] = &["x86_64", "amd64", "x64"];
    const ARM64: &[&str] = &["aarch64", "arm64"];

    // Fail-closed (F5): the target MUST POSITIVELY name this host's OS and CPU
    // arch. A foreign, typo'd, or otherwise unrecognized target is now REJECTED
    // (previously an unrecognized string was accepted — fail-open — which let a
    // signed manifest with a mistyped/novel `platform_target` install the wrong
    // binary and brick the host). The signature + sha256 gates still apply; this
    // adds a fail-closed platform gate on top. Unknown HOST os/arch (a rustc
    // target this build was not taught to classify) still accepts, since we
    // cannot positively match what we cannot name.
    let os_ok = match std::env::consts::OS {
        "windows" => has(WIN),
        "macos" => has(MAC),
        "linux" => has(LIN),
        "freebsd" => has(BSD),
        _ => true, // unknown host OS — cannot gate
    };
    let arch_ok = match std::env::consts::ARCH {
        "x86_64" => has(X64),
        "aarch64" => has(ARM64),
        _ => true, // unknown host arch — cannot gate
    };
    os_ok && arch_ok
}

/// Outcome of a successful apply. Returned to the caller so
/// `veil-cli update --apply` can render an actionable message
/// ("installed v1.3.0; restart with `systemctl restart veil`")
/// and a future runtime-driven applier can decide when to
/// restart.
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub previous_release_unix: u64,
    pub new_release_unix: u64,
    pub install_path: PathBuf,
    /// `true` on Unix where the binary file was successfully made
    /// executable; `false` on Windows where +x is implicit. Lets
    /// the CLI print the right post-apply message.
    pub binary_marked_executable: bool,
    /// `Some(path)` on Windows when `install_path` was already
    /// occupied by a (possibly running) binary that we relocated
    /// to `<install_path>.update-old` to make room for the new
    /// binary. `None` on POSIX (atomic rename clobbers without
    /// relocation) AND on Windows when `install_path` didn't
    /// exist (fresh install). Caller renders this in operator
    /// message ("old binary kept at X — will be deleted on next
    /// startup") and the next-startup `cleanup_stale_update_artifacts`
    /// removes the leftover.
    pub previous_binary_relocated_to: Option<PathBuf>,
    /// C-08: `true` when the apply adopted a LEGACY (unauthenticated, no-mac)
    /// installed-version file and re-wrote it MAC-authenticated — a one-time
    /// trust-on-first-use migration. The CLI surfaces this so a repeated no-mac
    /// downgrade attempt is visible rather than silent. Always `false` for an
    /// unkeyed store or a fresh install (no prior state file).
    pub migrated_legacy_state: bool,
}

/// Optional knobs for [`apply_update_with_options`]. `Default` is the safe
/// posture — every field off — so plain [`apply_update`] never relaxes a
/// security gate.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Authorize a one-time migration from a LEGACY (pre-C-08, no-MAC)
    /// installed-version file to the MAC-authenticated form. Default `false`:
    /// a keyed store that finds an unauthenticated record is REFUSED
    /// ([`ApplyError::LegacyStateMigrationRequired`]) rather than adopted,
    /// because a stripped MAC would otherwise re-open the anti-downgrade
    /// window. Set `true` only for the deliberate operator-driven migration.
    pub allow_legacy_state_migration: bool,
    /// Operator-asserted anti-downgrade floor (unix seconds) for an AUTHORIZED
    /// legacy migration. During such a migration the on-disk `release_unix` is
    /// UNAUTHENTICATED (no MAC) and is therefore NOT trusted; the anti-downgrade
    /// check uses THIS value instead (default `0` = accept the signature-,
    /// freshness-, platform-verified manifest as the new baseline). Lets the
    /// operator vouch for a minimum so a stripped/lowered state file cannot wave
    /// through an older but still-validly-signed manifest. Ignored on the normal
    /// (authenticated / fresh-install) path.
    pub legacy_migration_floor: Option<u64>,
}

/// Apply a fetched + verified update. Steps in order:
///
/// 1. Recompute SHA-256 of `binary_bytes` and verify against
///    `manifest.binary_sha256` (defence in depth).
/// 2. Enforce anti-downgrade: `manifest.release_unix` must be
///    strictly greater than the value in `store`. Equal is
///    rejected (forces operators to monotonically advance
///    timestamps so accidental re-publish doesn't bump
///    installation).
/// 3. Atomic write: stage to `<install_path>.tmp`, fsync, set
///    executable bit (Unix), rename to `install_path`.
/// 4. Persist new `release_unix` to `store`.
///
/// `current_version` is the running PRODUCT binary's version (the calling
/// binary crate's `CARGO_PKG_VERSION`), used for the `min_compatible_version`
/// gate in step 2c. It is a parameter rather than this library's own
/// `CARGO_PKG_VERSION` so the gate never compares against the wrong crate's
/// version once the product is versioned independently of `veil-update`
/// (C-07).
pub fn apply_update(
    manifest: &VerifiedManifest,
    binary_bytes: &[u8],
    install_path: &Path,
    store: &InstalledVersionStore,
    current_version: &str,
) -> Result<ApplyOutcome, ApplyError> {
    apply_update_with_options(
        manifest,
        binary_bytes,
        install_path,
        store,
        current_version,
        &ApplyOptions::default(),
    )
}

/// Like [`apply_update`] but takes explicit [`ApplyOptions`]. Plain
/// `apply_update` is the safe-default wrapper (`ApplyOptions::default()`, so
/// legacy no-MAC state migration is DISABLED). Use this variant only on the
/// deliberate operator-authorized migration path.
pub fn apply_update_with_options(
    manifest: &VerifiedManifest,
    binary_bytes: &[u8],
    install_path: &Path,
    store: &InstalledVersionStore,
    current_version: &str,
    opts: &ApplyOptions,
) -> Result<ApplyOutcome, ApplyError> {
    // Step 1: recompute SHA-256 (defence in depth).
    let mut hasher = Sha256::new();
    hasher.update(binary_bytes);
    let computed: [u8; BINARY_SHA256_LEN] = hasher.finalize().into();
    if computed != manifest.binary_sha256 {
        return Err(ApplyError::Sha256Mismatch {
            expected_hex: veil_util::bytes_to_hex(&manifest.binary_sha256),
            got_hex: veil_util::bytes_to_hex(&computed),
        });
    }

    // Step 2: anti-downgrade. Read current installed release_unix;
    // missing state file → 0 (fresh install — any positive
    // release_unix is "newer").
    let (installed_opt, migrated_legacy_state) = store.read_release_unix_for_apply()?;
    // C-08 hardening: a keyed store that finds an UNAUTHENTICATED (no-MAC,
    // legacy) record must not silently adopt it. A local writer who can reach
    // the state file but not the HMAC key could strip the MAC, lower the
    // recorded floor, and re-open the anti-downgrade window (then replay an
    // older, still-validly-signed manifest). Refuse by default; a genuine
    // one-time migration from a pre-C-08 install is an explicit opt-in
    // (`ApplyOptions::allow_legacy_state_migration`).
    if migrated_legacy_state && !opts.allow_legacy_state_migration {
        return Err(ApplyError::LegacyStateMigrationRequired);
    }
    // Anti-downgrade floor. Normal (authenticated / fresh-install) apply uses the
    // trusted recorded value. On an AUTHORIZED legacy migration the on-disk value
    // is UNAUTHENTICATED (no MAC) and could have been stripped + lowered by a
    // local writer, so we DO NOT use it — we use the operator-asserted floor
    // (`legacy_migration_floor`, default 0). `store.write(manifest.release_unix)`
    // below records the new floor MAC-authenticated, so normal anti-downgrade
    // resumes on the very next apply.
    // `previous` is informational only (recorded in the outcome). The
    // anti-downgrade GATE uses `previous` on the normal path, but on an
    // authorized legacy migration it uses the operator-asserted floor instead —
    // the on-disk `previous` is unauthenticated and must not gate.
    let previous = installed_opt.unwrap_or(0);
    let anti_downgrade_floor = if migrated_legacy_state {
        opts.legacy_migration_floor.unwrap_or(0)
    } else {
        previous
    };
    if manifest.release_unix <= anti_downgrade_floor {
        return Err(ApplyError::AntiDowngrade {
            manifest: manifest.release_unix,
            installed: anti_downgrade_floor,
        });
    }

    // Step 2b (audit U5): refuse a binary whose manifest names a DIFFERENT
    // platform than this host. Without this, per-platform manifests published
    // under one shared `manifest_urls` set could overwrite `install_path` with
    // a wrong-arch/wrong-OS binary that then fails to exec — a reboot-surviving
    // brick. The check is tolerant of the operator's platform_target naming
    // convention (rejects only a clearly-foreign OS/arch); see
    // `host_matches_platform_target`. Checked BEFORE the version-compat gate:
    // a wrong-platform binary can never apply regardless of version, and the
    // platform reject is the more fundamental "this artifact is not for you".
    if !host_matches_platform_target(&manifest.platform_target) {
        return Err(ApplyError::PlatformMismatch {
            manifest_target: manifest.platform_target.clone(),
            host_os: std::env::consts::OS,
            host_arch: std::env::consts::ARCH,
        });
    }

    // Step 2c (cycle-7 M5): enforce the manifest's min_compatible_version. A
    // signed manifest sets this when the release requires a mandatory
    // intermediate migration (state-format bump, key rotation, …); applying it
    // from a too-old binary would skip that migration and could corrupt state.
    //
    // C-07: the running PRODUCT binary's version is authoritative, and the
    // caller passes it in `current_version`. This used to read
    // `env!("CARGO_PKG_VERSION")`, which bakes in the version of the
    // `veil-update` LIBRARY crate at compile time — fine only while every
    // workspace crate shares one version (today, 0.1.0), but the moment the
    // product binary is versioned independently of this library crate the gate
    // would compare against the wrong number. Sourcing it from the caller (a
    // binary crate that knows its own `CARGO_PKG_VERSION`) removes that latent
    // drift. (Previously the signed `min_compatible_version` field was inert —
    // checked by nothing.)
    min_compatible_satisfied(current_version, &manifest.min_compatible_version)?;

    // Step 3: atomic stage + +x + rename. The staging file is created next to
    // `install_path` with an UNPREDICTABLE name, `O_EXCL`+`O_NOFOLLOW`, written,
    // fsync'd, and chmod'd executable BEFORE the rename — so a less-trusted user
    // with write access to the install directory cannot pre-place a symlink at a
    // predictable tmp path to capture or clobber the privileged write.
    let tmp_path = veil_util::write_executable_staged(install_path, binary_bytes)?;
    let binary_marked_executable = cfg!(unix);

    // Step 3a (Windows-only):.old-shuffle to make room for the
    // new binary BEFORE the rename. Windows' MoveFileEx with
    // REPLACE_EXISTING fails ERROR_ACCESS_DENIED when the target
    // is the running.exe — but RENAMING the running.exe to a
    // different name IS allowed (NTFS lets you rename an open
    // file; only delete-and-replace is blocked). So:
    //
    // 1. install_path → install_path.update-old (allowed: open file rename)
    // 2. tmp_path → install_path (allowed: target doesn't exist)
    // 3. Running process keeps the.update-old open by handle.
    // 4. Next-startup `cleanup_stale_update_artifacts` deletes
    // the.update-old (allowed: old process exited, no
    // handle holds it).
    //
    // POSIX skips this entirely — atomic rename clobbers the
    // existing install_path and the kernel keeps the old inode
    // alive on the running process. See module-level rustdoc.
    let previous_binary_relocated_to =
        relocate_running_binary_if_needed(install_path).map_err(|e| {
            // Cleanup staging file on the relocate failure path so
            // we don't leak it across retries (next apply retries
            // from a clean state).
            let _ = std::fs::remove_file(&tmp_path);
            ApplyError::Io(e)
        })?;

    // Step 3b: atomic rename of staging → install_path. After
    // 3a the install_path either doesn't exist (Windows
    // shuffle-out) or doesn't exist in any meaningful sense
    // (POSIX clobber semantics) — either way the rename succeeds.
    if let Err(e) = std::fs::rename(&tmp_path, install_path) {
        // Best-effort cleanup of the staging file so we don't
        // leak it across retries.
        let _ = std::fs::remove_file(&tmp_path);
        // Best-effort: if Windows shuffle-out succeeded but
        // rename-in failed, try to put the old binary back so the
        // running process / future restart still has something to
        // run from. Failures here are non-fatal — operator
        // recovers via next apply or manual file move.
        if let Some(ref old_path) = previous_binary_relocated_to {
            let _ = std::fs::rename(old_path, install_path);
        }
        return Err(ApplyError::Io(e));
    }

    // fsync the parent directory. `rename` is
    // atomic in kernel but not durable until the directory entry is
    // flushed. Without this, a power loss between the rename and the
    // next sync barrier can roll back the directory entry — the
    // install_path inode survives but the dirent points back to the
    //.tmp path, leaving the user with a half-applied update.
    //
    // POSIX: open(parent, O_RDONLY) then fsync. Windows: documented
    // not to support directory fsync; std skips it on this platform.
    // Best-effort — a fsync failure here means the update is committed
    // to page cache but not to disk, which is the same risk as a power
    // loss in the immediate window after rename. Don't fail the
    // apply: the bytes ARE on disk under the tmp path on retry, and a
    // subsequent apply will re-stage cleanly.
    if let Some(parent) = install_path.parent()
        && let Ok(dir_file) = std::fs::File::open(parent)
    {
        let _ = dir_file.sync_all();
    }

    // Step 4: persist new release_unix. Crash here means binary
    // is updated but state file lags — next apply re-runs cleanly
    // (sha256 still matches; anti-downgrade still passes against
    // OLD installed value); no silent corruption.
    store.write(manifest.release_unix)?;

    Ok(ApplyOutcome {
        previous_release_unix: previous,
        new_release_unix: manifest.release_unix,
        install_path: install_path.to_path_buf(),
        binary_marked_executable,
        previous_binary_relocated_to,
        migrated_legacy_state,
    })
}

/// Cleanup leftover `.update-old` and `.update-tmp` artifacts
/// from a previous apply (Windows.old-shuffle or crashed apply
/// mid-stage). Call from runtime startup so the disk doesn't
/// accumulate stale artifacts across many updates.
///
/// Both operations are best-effort — a stale artifact that we
/// can't delete (someone else holds an open handle, EACCES, etc)
/// is logged and skipped. No error is returned because there's
/// nothing operator-actionable in "cleanup of an old artifact
/// failed" — the next apply will retry from a clean state.
///
/// Returns the list of paths that WERE successfully cleaned up
/// (for caller to log / report — empty list = nothing to clean).
pub fn cleanup_stale_update_artifacts(install_path: &Path) -> Vec<PathBuf> {
    let mut cleaned = Vec::new();
    // Deterministic artifacts: `.update-old` (Windows shuffle-out) and the
    // legacy fixed `.update-tmp` staging name.
    for path in [with_old_suffix(install_path), with_tmp_suffix(install_path)] {
        if path.exists() && std::fs::remove_file(&path).is_ok() {
            cleaned.push(path);
        }
    }
    // Hardened staging now uses an unpredictable `<install>.update-tmp.<rand>`
    // suffix (`veil_util::write_executable_staged`); sweep those siblings too so
    // a crash mid-apply doesn't leak disk. Best-effort, like the rest.
    if let (Some(parent), Some(stem)) = (install_path.parent(), install_path.file_name()) {
        let mut marker = stem.to_owned();
        marker.push(".update-tmp.");
        let marker = marker.as_encoded_bytes().to_vec();
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                if entry.file_name().as_encoded_bytes().starts_with(&marker) {
                    let p = entry.path();
                    if std::fs::remove_file(&p).is_ok() {
                        cleaned.push(p);
                    }
                }
            }
        }
    }
    cleaned
}

/// Windows-only: relocate an existing binary at `install_path`
/// to `<install_path>.update-old` so the new binary can take
/// its place. Allowed on Windows even when the binary is
/// currently running (NTFS rename of open file). No-op when
/// `install_path` doesn't exist (fresh install — nothing to
/// relocate).
///
/// POSIX returns `Ok(None)` unconditionally — atomic rename
/// clobbers the existing target and the kernel keeps the old
/// inode alive on the running process, no shuffle needed.
#[cfg(windows)]
fn relocate_running_binary_if_needed(install_path: &Path) -> std::io::Result<Option<PathBuf>> {
    if !install_path.exists() {
        return Ok(None);
    }
    let old_path = with_old_suffix(install_path);
    // Best-effort cleanup of any stale.update-old (from a
    // previous failed apply that didn't recover all the way).
    // Ignoring errors — it may be locked by an even older
    // running process; if so, the rename below will fail loudly
    // and operator gets a clear "old binary handle held" diagnostic.
    let _ = std::fs::remove_file(&old_path);
    std::fs::rename(install_path, &old_path)?;
    Ok(Some(old_path))
}

#[cfg(not(windows))]
fn relocate_running_binary_if_needed(_install_path: &Path) -> std::io::Result<Option<PathBuf>> {
    Ok(None)
}

fn with_old_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".update-old");
    PathBuf::from(s)
}

fn with_tmp_suffix(path: &Path) -> PathBuf {
    // We use `.update-tmp` (not `.tmp`) to avoid colliding with
    // any operator's existing convention for that extension.
    let mut s = path.as_os_str().to_owned();
    s.push(".update-tmp");
    PathBuf::from(s)
}

// Executable staging (write + fsync + chmod-before-rename) moved to the
// hardened `veil_util::write_executable_staged` (unpredictable name +
// `O_EXCL`/`O_NOFOLLOW`) — see Step 3 of `apply_update_with_options`.

// local `bytes_hex` removed — use `veil_util::bytes_to_hex`.

#[cfg(test)]
mod tests {
    use super::super::manifest::{decode_manifest, sign_manifest};
    use super::*;
    use std::time::SystemTime;
    use veil_crypto::generate_keypair;
    use veil_types::SignatureAlgorithm;

    fn unique_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("veil-apply-{label}-{pid}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_manifest(release_unix: u64, sha256: [u8; 32]) -> VerifiedManifest {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        // Use the RUNNING host's platform so the U5 platform gate
        // (`host_matches_platform_target`) passes regardless of which OS/arch
        // the test suite runs on (Linux CI, macOS dev box, etc.).
        let host_pt = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        // `min_compatible_version` must be <= this crate's CARGO_PKG_VERSION
        // (0.1.0) or the cycle-7 M5 gate (`min_compatible_satisfied`, Step 2c
        // of `apply`) rejects every fixture before the test's real assertions
        // run. These tests exercise the file-swap mechanics, not version-compat
        // (that is `min_compatible_gate`'s job), so pin a min below 0.1.0.
        let bytes = sign_manifest(
            release_unix,
            "1.2.3",
            "0.0.1",
            &host_pt,
            sha256,
            vec!["https://bin.example/x".to_owned()],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        // Tests here exercise apply-side mechanics (file swap, anti-downgrade,
        // platform/version gates), not signature verification — wrap without
        // re-verifying via the cfg(test)-only constructor.
        VerifiedManifest::assume_verified(decode_manifest(&bytes).unwrap())
    }

    /// audit U5: `host_matches_platform_target` rejects a clearly-foreign OS or
    /// CPU arch but accepts the host platform in either naming convention.
    #[test]
    fn min_compatible_gate() {
        // current >= min → ok
        assert!(min_compatible_satisfied("1.2.3", "1.0.0").is_ok());
        assert!(min_compatible_satisfied("1.0.0", "1.0.0").is_ok());
        // current < min → IncompatibleVersion (skips a mandatory migration)
        assert!(matches!(
            min_compatible_satisfied("0.9.0", "1.0.0"),
            Err(ApplyError::IncompatibleVersion { .. })
        ));
        // empty / whitespace min → no constraint (signature is the real gate)
        assert!(min_compatible_satisfied("1.0.0", "").is_ok());
        assert!(min_compatible_satisfied("1.0.0", "   ").is_ok());
        // present-but-unparseable min → fail-closed reject (a malformed bound
        // must not be silently treated as "no constraint")
        assert!(matches!(
            min_compatible_satisfied("1.0.0", "not-a-version"),
            Err(ApplyError::MalformedVersionConstraint { .. })
        ));
        // the actual running binary clears a permissive floor
        assert!(min_compatible_satisfied(env!("CARGO_PKG_VERSION"), "0.0.1").is_ok());
    }

    #[test]
    fn u5_platform_gate_token_match() {
        // Foreign OS (relative to host) is rejected.
        let foreign_os = if std::env::consts::OS == "windows" {
            "x86_64-unknown-linux-gnu"
        } else {
            "x86_64-pc-windows-msvc"
        };
        assert!(!host_matches_platform_target(foreign_os));
        // Foreign CPU arch is rejected.
        let foreign_arch = if std::env::consts::ARCH == "x86_64" {
            "aarch64-some-os"
        } else {
            "x86_64-some-os"
        };
        assert!(!host_matches_platform_target(foreign_arch));
        // Host platform accepted in both conventions.
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        assert!(host_matches_platform_target(&format!("{os}-{arch}")));
        assert!(host_matches_platform_target(&format!(
            "{arch}-unknown-{os}-gnu"
        )));
        // F5: an unrecognized target is now REJECTED fail-closed (was accepted).
        assert!(!host_matches_platform_target("unrecognized-format"));
    }

    /// audit U5: apply_update refuses a signed manifest whose platform_target
    /// names a different OS than the host (correct sha256 + fresh release_unix,
    /// so only the platform gate can reject) — prevents the wrong-binary brick.
    #[test]
    fn u5_apply_rejects_foreign_platform_binary() {
        let dir = unique_dir("platform-mismatch");
        let install = dir.join("veil");
        let store = InstalledVersionStore::new(dir.join("installed.json"));
        let payload = b"foreign-platform binary";
        let foreign = if std::env::consts::OS == "windows" {
            "x86_64-unknown-linux-gnu"
        } else {
            "x86_64-pc-windows-msvc"
        };
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let bytes = sign_manifest(
            2_000_000_000,
            "1.2.3",
            "1.0.0",
            foreign,
            sha256_of(payload),
            vec!["https://bin.example/x".to_owned()],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let manifest = VerifiedManifest::assume_verified(decode_manifest(&bytes).unwrap());
        let err = apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::PlatformMismatch { .. }),
            "expected PlatformMismatch, got {err:?}"
        );
        assert!(
            !install.exists(),
            "foreign-platform binary must not be written"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn sha256_of(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn epic484_3_apply_happy_path_writes_binary_and_updates_state() {
        let dir = unique_dir("happy-path");
        let install = dir.join("veil");
        let state = dir.join("installed.json");
        let store = InstalledVersionStore::new(state.clone());

        let payload = b"this is the new binary";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));

        let outcome = apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        // Binary is at install_path with the right bytes.
        let on_disk = std::fs::read(&install).unwrap();
        assert_eq!(on_disk, payload);
        assert_eq!(outcome.previous_release_unix, 0);
        assert_eq!(outcome.new_release_unix, 2_000_000_000);
        assert_eq!(outcome.install_path, install);

        // State file records the new release_unix.
        assert_eq!(store.read_release_unix().unwrap(), Some(2_000_000_000));

        // No leaked.tmp file.
        assert!(
            !with_tmp_suffix(&install).exists(),
            "staging file must be cleaned up after rename"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_rejects_sha256_mismatch_defence_in_depth() {
        let dir = unique_dir("sha-mismatch");
        let install = dir.join("veil");
        let store = InstalledVersionStore::new(dir.join("installed.json"));

        let payload = b"actual binary bytes";
        // Manifest claims a DIFFERENT sha256 — caller bug or
        // tampered transport. Apply must reject loudly even though
        // fetch supposedly verified earlier.
        let lying_manifest = fixture_manifest(2_000_000_000, [0xAB; 32]);

        let err = apply_update(
            &lying_manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Sha256Mismatch { .. }));
        // No binary written.
        assert!(
            !install.exists(),
            "binary must NOT be written when sha256 mismatches"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_rejects_anti_downgrade() {
        let dir = unique_dir("anti-downgrade");
        let install = dir.join("veil");
        let state = dir.join("installed.json");
        let store = InstalledVersionStore::new(state);
        store.write(2_000_000_000).unwrap();

        // Manifest is OLDER than what's installed — censor captures
        // an old signed manifest and tries to roll us back.
        let old_payload = b"older binary";
        let old_manifest = fixture_manifest(1_500_000_000, sha256_of(old_payload));

        let err = apply_update(
            &old_manifest,
            old_payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        match err {
            ApplyError::AntiDowngrade {
                manifest,
                installed,
            } => {
                assert_eq!(manifest, 1_500_000_000);
                assert_eq!(installed, 2_000_000_000);
            }
            other => panic!("expected AntiDowngrade, got {other:?}"),
        }
        assert!(
            !install.exists(),
            "binary must NOT be written on anti-downgrade rejection"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_rejects_equal_release_anti_downgrade() {
        // Boundary: manifest.release_unix == installed. Must be
        // rejected (equal is "no new version" — operator pushed
        // same timestamp twice; could be accident or could be
        // censor re-serving a captured manifest).
        let dir = unique_dir("equal-rejected");
        let install = dir.join("veil");
        let store = InstalledVersionStore::new(dir.join("installed.json"));
        store.write(1_700_000_000).unwrap();

        let payload = b"same release";
        let manifest = fixture_manifest(1_700_000_000, sha256_of(payload));

        let err = apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::AntiDowngrade { .. }),
            "equal release_unix must be rejected as anti-downgrade"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_replaces_existing_install_atomically() {
        // Pre-existing binary at install_path; apply must REPLACE
        // it cleanly (not error "file exists").
        let dir = unique_dir("replace");
        let install = dir.join("veil");
        std::fs::write(&install, b"OLD binary at install path").unwrap();
        let store = InstalledVersionStore::new(dir.join("installed.json"));
        store.write(1_500_000_000).unwrap();

        let new_payload = b"NEW binary v1.3.0";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(new_payload));

        apply_update(
            &manifest,
            new_payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        let after = std::fs::read(&install).unwrap();
        assert_eq!(after, new_payload, "install_path must hold the NEW binary");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn epic484_3_apply_marks_binary_executable_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("chmod");
        let install = dir.join("veil");
        let store = InstalledVersionStore::new(dir.join("installed.json"));

        let payload = b"executable binary";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));

        let outcome = apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        assert!(outcome.binary_marked_executable);

        let perms = std::fs::metadata(&install).unwrap().permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "installed binary must be 0o755 (rwxr-xr-x), got 0o{mode:o}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_creates_parent_dir_when_missing() {
        // Operator points install_path at a deeper path that
        // doesn't exist yet (e.g. /var/lib/veil/bin/veil
        // on a fresh system where /var/lib/veil/bin hasn't
        // been mkdir'd). Apply must create the parent rather
        // than error out.
        let dir = unique_dir("mkdir");
        let install = dir.join("nested").join("subdir").join("veil");
        let store = InstalledVersionStore::new(dir.join("installed.json"));

        let payload = b"bin";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));

        apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        assert!(
            install.exists(),
            "binary must be written even when parent dir was missing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_does_not_touch_unrelated_files_in_install_dir() {
        // Apply must REPLACE only install_path; identity files
        // logs, configs in the same directory must be untouched.
        // Defends against a regression that accidentally rm-rfs
        // the parent dir.
        let dir = unique_dir("isolation");
        let install = dir.join("veil");
        let identity_neighbour = dir.join("identity.json");
        let config_neighbour = dir.join("config.toml");
        std::fs::write(&identity_neighbour, b"DO NOT TOUCH me").unwrap();
        std::fs::write(&config_neighbour, b"operator config bytes").unwrap();
        let store = InstalledVersionStore::new(dir.join("installed.json"));

        let payload = b"new binary";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));
        apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        // Neighbours untouched.
        assert_eq!(
            std::fs::read(&identity_neighbour).unwrap(),
            b"DO NOT TOUCH me",
            "identity neighbour must NOT be touched by apply"
        );
        assert_eq!(
            std::fs::read(&config_neighbour).unwrap(),
            b"operator config bytes",
            "config neighbour must NOT be touched by apply"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_apply_outcome_carries_previous_release_unix_for_rollback_messaging() {
        // The CLI / GUI presents "upgraded from v1 to v2" — needs
        // both numbers. Verify outcome carries them.
        let dir = unique_dir("outcome");
        let install = dir.join("veil");
        let store = InstalledVersionStore::new(dir.join("installed.json"));
        store.write(1_500_000_000).unwrap();

        let payload = b"new bin";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));
        let outcome = apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        assert_eq!(outcome.previous_release_unix, 1_500_000_000);
        assert_eq!(outcome.new_release_unix, 2_000_000_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── sub-slice: Windows.old-shuffle wrapper ──────────────

    #[cfg(not(windows))]
    #[test]
    fn epic484_3_posix_apply_does_not_produce_update_old_artifact() {
        // POSIX semantics: atomic rename clobbers existing
        // install_path and kernel keeps old inode alive on running
        // process — no.old-shuffle needed, no.update-old artifact
        // produced. Outcome's previous_binary_relocated_to MUST
        // be None on POSIX so operator log doesn't say "old binary
        // moved to X" when nothing was actually moved.
        let dir = unique_dir("posix-no-old");
        let install = dir.join("veil");
        std::fs::write(&install, b"OLD bin").unwrap();
        let store = InstalledVersionStore::new(dir.join("installed.json"));

        let payload = b"NEW bin";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));
        let outcome = apply_update(
            &manifest,
            payload,
            &install,
            &store,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        assert!(
            outcome.previous_binary_relocated_to.is_none(),
            "POSIX must NOT produce .update-old artifact (atomic rename clobbers)"
        );
        // No.update-old file on disk either.
        assert!(
            !with_old_suffix(&install).exists(),
            "POSIX apply must leave no .update-old artifact"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_cleanup_stale_artifacts_removes_update_old() {
        // Test the cleanup helper platform-agnostically by manually
        // creating both stale artifacts and asserting they're
        // removed. This locks in the contract for the runtime
        // startup path that calls cleanup_stale_update_artifacts.
        let dir = unique_dir("cleanup-old");
        let install = dir.join("veil");
        // Pre-create install_path so the helper's logic doesn't
        // accidentally treat it as a stale artifact.
        std::fs::write(&install, b"current binary").unwrap();
        let stale_old = with_old_suffix(&install);
        let stale_tmp = with_tmp_suffix(&install);
        std::fs::write(&stale_old, b"stale old binary").unwrap();
        std::fs::write(&stale_tmp, b"stale tmp from crashed apply").unwrap();

        let cleaned = cleanup_stale_update_artifacts(&install);

        // Both stale artifacts removed.
        assert!(!stale_old.exists(), ".update-old must be cleaned");
        assert!(!stale_tmp.exists(), ".update-tmp must be cleaned");
        // install_path itself untouched.
        assert!(
            install.exists(),
            "install_path must NOT be touched by cleanup"
        );
        let install_content = std::fs::read(&install).unwrap();
        assert_eq!(
            install_content, b"current binary",
            "cleanup must NOT modify install_path content"
        );
        // Both cleaned paths reported back so caller can log them.
        assert_eq!(cleaned.len(), 2);
        assert!(cleaned.contains(&stale_old));
        assert!(cleaned.contains(&stale_tmp));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_cleanup_stale_artifacts_no_op_when_no_artifacts() {
        // No.update-old or.update-tmp on disk → cleanup is a
        // no-op, returns empty list, no error. This is the
        // common-case path on every node startup.
        let dir = unique_dir("cleanup-noop");
        let install = dir.join("veil");
        std::fs::write(&install, b"current binary").unwrap();

        let cleaned = cleanup_stale_update_artifacts(&install);
        assert!(
            cleaned.is_empty(),
            "cleanup must return empty list when no artifacts exist"
        );
        assert!(install.exists(), "install_path must remain intact");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_cleanup_stale_artifacts_partial_only_removes_what_exists() {
        // Only.update-old present.update-tmp absent → cleanup
        // removes the.update-old and returns it; doesn't error on
        // the absent.update-tmp. Verifies we don't accidentally
        // require BOTH to be present for cleanup to work.
        let dir = unique_dir("cleanup-partial");
        let install = dir.join("veil");
        std::fs::write(&install, b"current binary").unwrap();
        let stale_old = with_old_suffix(&install);
        std::fs::write(&stale_old, b"stale").unwrap();

        let cleaned = cleanup_stale_update_artifacts(&install);
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0], stale_old);
        assert!(!stale_old.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epic484_3_with_old_suffix_appends_update_old_extension() {
        // Lock in the suffix name so a future rename doesn't
        // silently break the cleanup helper (which reconstructs
        // the same path via the same helper — but if the runtime's
        // startup-cleanup ever caches the suffix string, the
        // mismatch would silently leak artifacts).
        let p = with_old_suffix(Path::new("/opt/veil/bin/veil"));
        assert_eq!(p, PathBuf::from("/opt/veil/bin/veil.update-old"));
    }

    #[test]
    fn epic484_3_relocate_helper_returns_none_on_missing_install_path() {
        // Fresh install (install_path doesn't exist yet) —
        // relocation helper must return None, NOT an io::Error.
        // This is the pre-Step-3a state on a brand-new node;
        // erroring here would block any first install.
        let dir = unique_dir("relocate-missing");
        let install = dir.join("never-existed");
        let result = relocate_running_binary_if_needed(&install).unwrap();
        assert!(
            result.is_none(),
            "missing install_path must return None (fresh install path)"
        );
        // Confirm we didn't accidentally create the.update-old.
        assert!(!with_old_suffix(&install).exists());
    }

    #[test]
    fn c08_apply_migrates_legacy_unauthenticated_state() {
        // A node that applied an update before C-08 has a legacy (no-mac)
        // installed.json. The first KEYED apply, WHEN EXPLICITLY AUTHORIZED via
        // `allow_legacy_state_migration`, must adopt it once (migration), flag
        // `migrated_legacy_state`, and re-write it authenticated. (Without the
        // opt-in the apply refuses — see
        // `c08_apply_refuses_legacy_state_without_optin`.)
        let dir = unique_dir("c08-migrate");
        let install = dir.join("veil");
        let state = dir.join("installed.json");

        // Pre-C-08 state file: written by the unkeyed store.
        InstalledVersionStore::new(state.clone())
            .write(1_900_000_000)
            .unwrap();
        assert!(
            !std::fs::read_to_string(&state).unwrap().contains("\"mac\""),
            "precondition: legacy file has no mac"
        );

        let keyed = InstalledVersionStore::with_hmac_key(state.clone(), [0x5Au8; 32]);
        let payload = b"new authenticated binary";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));
        let outcome = apply_update_with_options(
            &manifest,
            payload,
            &install,
            &keyed,
            env!("CARGO_PKG_VERSION"),
            &ApplyOptions {
                allow_legacy_state_migration: true,
                legacy_migration_floor: None,
            },
        )
        .unwrap();

        assert!(
            outcome.migrated_legacy_state,
            "first authorized keyed apply over a legacy file must flag the migration"
        );
        assert_eq!(outcome.previous_release_unix, 1_900_000_000);
        assert_eq!(outcome.new_release_unix, 2_000_000_000);
        assert!(
            std::fs::read_to_string(&state).unwrap().contains("\"mac\""),
            "post-migration file must carry a mac"
        );

        // A second keyed apply over the now-authenticated file is NOT a migration.
        let payload2 = b"even newer binary";
        let manifest2 = fixture_manifest(2_100_000_000, sha256_of(payload2));
        let outcome2 = apply_update(
            &manifest2,
            payload2,
            &install,
            &keyed,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        assert!(
            !outcome2.migrated_legacy_state,
            "steady-state apply over an authenticated file is not a migration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c08_apply_rejects_tampered_authenticated_state() {
        // Once authenticated, an attacker who edits release_unix in place (mac
        // present but invalid) must be fail-closed by the apply — never silently
        // accepted as a downgrade.
        let dir = unique_dir("c08-tamper");
        let install = dir.join("veil");
        let state = dir.join("installed.json");
        let keyed = InstalledVersionStore::with_hmac_key(state.clone(), [0x77u8; 32]);
        keyed.write(2_000_000_000).unwrap();

        // Attacker lowers the floor in place → mac mismatch.
        let raw = std::fs::read_to_string(&state).unwrap();
        std::fs::write(&state, raw.replace("2000000000", "1000000000")).unwrap();

        let payload = b"downgrade attempt binary";
        let manifest = fixture_manifest(1_500_000_000, sha256_of(payload));
        let err = apply_update(
            &manifest,
            payload,
            &install,
            &keyed,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ApplyError::InstalledVersion(InstalledVersionError::MacFailure)
            ),
            "tampered authenticated state must fail closed, got {err:?}"
        );
        assert!(
            !install.exists(),
            "no binary may be written when the anti-downgrade read fails"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c08_apply_refuses_legacy_state_without_optin() {
        // A keyed store that finds a legacy (no-mac) file must REFUSE by default
        // — silently adopting it is the strip-MAC downgrade vector. Migration is
        // an explicit opt-in (`allow_legacy_state_migration`), not automatic.
        let dir = unique_dir("c08-refuse-legacy");
        let install = dir.join("veil");
        let state = dir.join("installed.json");
        InstalledVersionStore::new(state.clone())
            .write(1_900_000_000)
            .unwrap();
        let keyed = InstalledVersionStore::with_hmac_key(state.clone(), [0x5Au8; 32]);
        let payload = b"binary";
        let manifest = fixture_manifest(2_000_000_000, sha256_of(payload));
        let err = apply_update(
            &manifest,
            payload,
            &install,
            &keyed,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::LegacyStateMigrationRequired),
            "default apply over a legacy no-mac keyed file must fail closed, got {err:?}"
        );
        assert!(
            !install.exists(),
            "no binary may be written on the legacy-refusal path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c08_apply_rejects_stripped_mac_downgrade() {
        // Regression (audit): write an AUTHENTICATED record at a high floor,
        // then an attacker STRIPS the mac and lowers release_unix to re-open the
        // migration window. The default apply must reject this rather than
        // adopting the lowered floor and accepting a replayed older manifest.
        let dir = unique_dir("c08-strip-mac");
        let install = dir.join("veil");
        let state = dir.join("installed.json");
        let keyed = InstalledVersionStore::with_hmac_key(state.clone(), [0x33u8; 32]);
        keyed.write(2_000_000_000).unwrap();
        assert!(
            std::fs::read_to_string(&state).unwrap().contains("\"mac\""),
            "precondition: authenticated record carries a mac"
        );

        // Strip the mac AND lower the floor — byte-identical to what a
        // strip-mac attacker writes (an unkeyed record at the lowered value).
        InstalledVersionStore::new(state.clone())
            .write(1_000_000_000)
            .unwrap();
        assert!(
            !std::fs::read_to_string(&state).unwrap().contains("\"mac\""),
            "attacker stripped the mac"
        );

        let payload = b"replayed older binary";
        let manifest = fixture_manifest(1_500_000_000, sha256_of(payload));
        let err = apply_update(
            &manifest,
            payload,
            &install,
            &keyed,
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::LegacyStateMigrationRequired),
            "stripped-mac lowered floor must be rejected, got {err:?}"
        );
        assert!(
            !install.exists(),
            "no binary may be written on the strip-mac downgrade path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c08_migration_ignores_unauthenticated_file_floor() {
        // M-1 (audit): during an AUTHORIZED legacy migration the unauthenticated
        // file's own release_unix must NOT gate anti-downgrade. An attacker who
        // stripped the MAC and lowered the floor to 0 must not wave through an
        // older signed manifest — the operator-asserted floor is used instead.
        let dir = unique_dir("c08-migrate-floor");
        let install = dir.join("veil");
        let state = dir.join("installed.json");
        // Attacker leaves a no-mac file with a LOWERED floor (0).
        InstalledVersionStore::new(state.clone()).write(0).unwrap();
        let keyed = InstalledVersionStore::with_hmac_key(state.clone(), [0x5Au8; 32]);
        let payload = b"older replayed binary";
        let manifest = fixture_manifest(1_500_000_000, sha256_of(payload));
        // Operator vouches the host legitimately reached >= 2_000_000_000.
        let err = apply_update_with_options(
            &manifest,
            payload,
            &install,
            &keyed,
            env!("CARGO_PKG_VERSION"),
            &ApplyOptions {
                allow_legacy_state_migration: true,
                legacy_migration_floor: Some(2_000_000_000),
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::AntiDowngrade { .. }),
            "older manifest must be rejected against the OPERATOR floor, not the file's 0; got {err:?}"
        );
        assert!(
            !install.exists(),
            "no binary written on the rejected migration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
