//! CLI handler for `veil-cli update …`.
//!
//! Operator-visible front-end for the update mechanism shipped in
//! slices 1-9. Composes:
//! * Loaded `Config` → operator's `[update]` section.
//! * `TransportContext::from_config` → tls-boring Chrome
//!   ClientHello fingerprint shared with HTTPS bootstrap (
//!   — single audit surface for DPI evasion.
//! * `UpdateChecker::check` → end-to-end orchestrator from.
//!
//! No admin socket required — the check runs against the operator's
//! HTTPS endpoints directly, so it works on a brand-new install
//! BEFORE the node has been started for the first time. This is
//! intentional: the operator's first action after install is often
//! "is this version current?" and that question must answer before
//! they spin up the daemon.

use tokio::runtime::Builder;

use veil_cfg;
use veil_update::apply::{ApplyError, ApplyOptions, apply_update_with_options};
use veil_update::checker::{CheckerError, UpdateChecker};
use veil_update::fetch::{FetchError, UpdateAvailability, fetch_binary_via_https};
use veil_update::installed_version::InstalledVersionStore;

use super::{
    cli::{UpdateArgs, UpdateCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
};

pub fn handle_update_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: UpdateArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        UpdateCommand::Check => update_check(&mut context),
        UpdateCommand::Apply {
            allow_legacy_state_migration,
        } => update_apply(&mut context, allow_legacy_state_migration),
        UpdateCommand::SignManifest(args) => update_sign_manifest(&mut context, args),
    }
}

/// build a signed `UpdateManifest` blob for a freshly-built
/// binary. Computes SHA-256 of the binary file, loads the issuer
/// identity from a TOML config file, signs, and writes the manifest
/// bytes to stdout / `--output`.
fn update_sign_manifest<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    args: super::cli::SignManifestArgs,
) -> veil_cfg::Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use veil_update::manifest::sign_manifest;

    // SHA-256 of the binary, streaming to keep memory bounded для
    // 10-30 MiB binaries (the.so / veil-cli outputs are ~10 MiB).
    let mut file = std::fs::File::open(&args.binary).map_err(|e| {
        veil_cfg::ConfigError::CommandFailed(format!("open binary {}: {e}", args.binary.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("read binary: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut binary_sha256 = [0u8; 32];
    binary_sha256.copy_from_slice(&digest);

    // Load issuer identity from the TOML file. Reuses the existing
    // [identity] section schema так что operators may sign manifests
    // с a key that ALSO acts как a node's signing key, OR с a
    // dedicated cold-storage release-signing key — same wire format.
    let identity_toml = std::fs::read_to_string(&args.identity).map_err(|e| {
        veil_cfg::ConfigError::CommandFailed(format!(
            "read identity {}: {e}",
            args.identity.display()
        ))
    })?;
    #[derive(serde::Deserialize)]
    struct IdentityFile {
        identity: veil_cfg::IdentityConfig,
    }
    let id_file: IdentityFile = toml::from_str(&identity_toml)
        .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("parse identity TOML: {e}")))?;
    let issuer_pk = id_file.identity.public_key;
    let issuer_sk = id_file.identity.private_key;
    let issuer_algo = match id_file.identity.algo {
        veil_cfg::SignatureAlgorithm::Ed25519 => veil_types::SignatureAlgorithm::Ed25519,
        veil_cfg::SignatureAlgorithm::Falcon512 => veil_types::SignatureAlgorithm::Falcon512,
        veil_cfg::SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid
        }
        veil_cfg::SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid
        }
    };

    let release_unix = args.release_unix.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let bytes = sign_manifest(
        release_unix,
        &args.version,
        &args.min_compatible_version,
        &args.platform_target,
        binary_sha256,
        args.binary_urls,
        &issuer_pk,
        &issuer_sk,
        issuer_algo,
    )
    .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("sign manifest: {e}")))?;

    let sha_hex: String = binary_sha256
        .iter()
        .fold(String::with_capacity(64), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        });

    if let Some(path) = args.output {
        std::fs::write(&path, &bytes).map_err(|e| {
            veil_cfg::ConfigError::CommandFailed(format!(
                "write manifest к {}: {e}",
                path.display()
            ))
        })?;
        context.io.emit(OutputEvent::message(format!(
            "wrote {} B signed manifest to {}\n  binary_sha256: {sha_hex}\n  version: {} \
             (min_compatible: {})\n  platform: {}\n  release_unix: {release_unix}",
            bytes.len(),
            path.display(),
            args.version,
            args.min_compatible_version,
            args.platform_target,
        )));
    } else {
        // Write raw manifest bytes к stdout via the IO emitter so
        // callers can pipe `> manifest.bin`. Emit informational
        // message к stderr first so it doesn't pollute the bytes.
        context.io.emit(OutputEvent::message(format!(
            "binary_sha256={sha_hex} version={} bytes={}",
            args.version,
            bytes.len(),
        )));
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("write to stdout: {e}")))?;
    }
    Ok(())
}

fn update_check<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
) -> veil_cfg::Result<()> {
    let (_, config) = context.config().load_existing()?;

    if !config.update.is_check_enabled() {
        return Err(veil_cfg::ConfigError::CommandFailed(
            "[update] section is not configured.  Set both `update.manifest_urls` (HTTPS \
             endpoints serving the operator's signed manifest) and `update.expected_issuer_pk` \
             (hex-encoded public key) to enable the check."
                .to_owned(),
        ));
    }

    let transport_ctx = veil_cfg::transport_glue::context_from_config(&config).map_err(|e| {
        veil_cfg::ConfigError::CommandFailed(format!("build transport context: {e}"))
    })?;

    let checker = UpdateChecker::new(config.update.clone(), transport_ctx);

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let result = runtime.block_on(checker.check());

    match result {
        Ok(UpdateAvailability::UpToDate {
            latest_release_unix,
        }) => {
            // Operator-friendly: convert release_unix to ISO-8601-ish
            // YYYY-MM-DD so a human reading the output knows
            // immediately when the operator last published.
            let date = format_unix_date(latest_release_unix);
            context.io.emit(OutputEvent::message(format!(
                "up to date (latest published: {date}, release_unix={latest_release_unix})"
            )));
            Ok(())
        }
        Ok(UpdateAvailability::Available { manifest }) => {
            let date = format_unix_date(manifest.release_unix);
            // Single multi-line block so JSON renderer keeps a
            // single Message event but the text renderer is human-
            // friendly.
            context.io.emit(OutputEvent::message(format!(
                "update available\n\
                 version: {version}\n\
                 release_unix: {release_unix} ({date})\n\
                 platform: {platform}\n\
                 binary_sha256: {sha256}\n\
                 binary_urls ({n_urls}):\n{urls}",
                version = manifest.version,
                release_unix = manifest.release_unix,
                date = date,
                platform = manifest.platform_target,
                sha256 = veil_util::bytes_to_hex(&manifest.binary_sha256),
                n_urls = manifest.binary_urls.len(),
                urls = manifest
                    .binary_urls
                    .iter()
                    .map(|u| format!("  - {u}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )));
            // Surface "update available" as a clean error so the CLI
            // exits with non-zero status — operators wiring this
            // into systemd timers / CI gates need to detect "yes
            // there's an update" via exit code, not by parsing
            // stdout.
            Err(veil_cfg::ConfigError::CommandFailed(format!(
                "update available: {} (released {date})",
                manifest.version,
            )))
        }
        Err(CheckerError::NotConfigured) => Err(veil_cfg::ConfigError::CommandFailed(
            // Should be unreachable because is_check_enabled was
            // checked above; if we're here, the orchestrator's
            // defence-in-depth caught a half-config that bypassed
            // validation. Surface verbatim.
            "checker reported NotConfigured despite is_check_enabled() returning true \
             — likely a missing field bypassed validation, run `veil-cli config validate` \
             to inspect"
                .to_owned(),
        )),
        Err(CheckerError::InstalledVersion(e)) => Err(veil_cfg::ConfigError::CommandFailed(
            format!("cannot read installed-version state: {e}"),
        )),
        Err(CheckerError::Fetch(e)) => Err(veil_cfg::ConfigError::CommandFailed(format!(
            "fetch failed: {e}"
        ))),
    }
}

/// C-08: derive the per-node HMAC key that authenticates the anti-downgrade
/// state file (`installed_version_path`).
///
/// Keyed off this node's SECRET Ed25519 identity seed, loaded from the standard
/// identity dir. The seed lives with the identity (typically `0600`), NOT next
/// to the state file, so an attacker who can write the state file but not the
/// identity dir cannot forge a MAC over a lowered release_unix. BLAKE3
/// `derive_key` domain-separates this from every other key derived from the
/// same seed.
///
/// Returns `None` — caller falls back to an unauthenticated store, no worse than
/// pre-C-08 — when the identity is not provisioned or exposes no Ed25519 key
/// (e.g. a Falcon-only identity).
fn installed_version_mac_key() -> Option<[u8; 32]> {
    let dir = veil_identity::sovereign_flow::default_identity_dir().ok()?;
    let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir).ok()?;
    let sk = sov.ed25519_signing_key()?;
    Some(blake3::derive_key(
        "veil.update.installed-version.mac.v1",
        &sk.to_bytes(),
    ))
}

fn update_apply<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    allow_legacy_state_migration: bool,
) -> veil_cfg::Result<()> {
    let (_, config) = context.config().load_existing()?;

    if !config.update.is_apply_enabled() {
        return Err(veil_cfg::ConfigError::CommandFailed(
            "[update] section is missing required apply-path fields. \
             Set `update.manifest_urls`, `update.expected_issuer_pk`, \
             `update.install_path` (where the binary lives), AND \
             `update.installed_version_path` (where to record the \
             installed release_unix)."
                .to_owned(),
        ));
    }

    // P1: both Option<PathBuf> are guaranteed Some by
    // is_apply_enabled, but a future refactor that drops the guard
    // must surface as a clean error rather than `panic = abort`.
    let install_path = config.update.install_path.clone().ok_or_else(|| {
        veil_cfg::ConfigError::CommandFailed(
            "internal: update.install_path missing despite is_apply_enabled".to_owned(),
        )
    })?;
    let state_path = config
        .update
        .installed_version_path
        .clone()
        .ok_or_else(|| {
            veil_cfg::ConfigError::CommandFailed(
                "internal: update.installed_version_path missing despite is_apply_enabled"
                    .to_owned(),
            )
        })?;
    // C-08: authenticate the anti-downgrade state file. The store is keyed with
    // an HMAC derived from this node's secret Ed25519 identity seed (loaded from
    // the standard identity dir), so a local attacker who can write
    // `installed_version_path` but NOT the operator's identity dir can no longer
    // rewrite the recorded release_unix to slip a replayed (legitimately-signed)
    // older manifest past the anti-downgrade gate. Falls back to an
    // unauthenticated store (no worse than before) when no Ed25519 identity is
    // available — see `installed_version_mac_key`.
    let store = match installed_version_mac_key() {
        Some(key) => InstalledVersionStore::with_hmac_key(state_path, key),
        None => {
            context.io.emit(OutputEvent::message(
                "warning: the anti-downgrade state file will NOT be \
                 MAC-authenticated — no Ed25519 identity was found at the \
                 default identity dir, so a local attacker able to rewrite it \
                 could lower the anti-downgrade floor. Run `veil-cli identity \
                 create` (or restore one) to enable authentication."
                    .to_owned(),
            ));
            InstalledVersionStore::new(state_path)
        }
    };

    let transport_ctx = veil_cfg::transport_glue::context_from_config(&config).map_err(|e| {
        veil_cfg::ConfigError::CommandFailed(format!("build transport context: {e}"))
    })?;

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;

    // Step 1: ask the checker whether an update is even available.
    // No point fetching the binary if we're already current.
    let checker = UpdateChecker::new(config.update.clone(), transport_ctx.clone());
    let availability = runtime.block_on(checker.check()).map_err(map_checker_err)?;
    let manifest = match availability {
        UpdateAvailability::UpToDate {
            latest_release_unix,
        } => {
            let date = format_unix_date(latest_release_unix);
            context.io.emit(OutputEvent::message(format!(
                "no update available — already at the latest published release \
                 ({date}, release_unix={latest_release_unix}); apply is a no-op"
            )));
            return Ok(());
        }
        UpdateAvailability::Available { manifest } => manifest,
    };

    // Step 2: fetch the binary from the manifest's URLs (failover
    // built into fetch_binary_via_https; SHA-256 verified by the
    // helper before bytes return; apply_update verifies AGAIN
    // defence-in-depth).
    let binary_bytes = runtime
        .block_on(fetch_binary_via_https(
            &manifest.binary_urls,
            transport_ctx,
            &manifest.binary_sha256,
        ))
        .map_err(map_fetch_err)?;

    // Step 3: atomic swap.
    // C-07: pass THIS binary's version (veil-cli is the product binary, so
    // its CARGO_PKG_VERSION is the authoritative installed version) for the
    // manifest's min_compatible_version gate — not the veil-update library
    // crate's own version.
    let outcome = apply_update_with_options(
        &manifest,
        &binary_bytes,
        &install_path,
        &store,
        env!("CARGO_PKG_VERSION"),
        &ApplyOptions {
            allow_legacy_state_migration,
        },
    )
    .map_err(map_apply_err)?;

    if outcome.migrated_legacy_state {
        // C-08 trust-on-first-use migration: surfaced so a repeated no-mac
        // downgrade attempt (an attacker stripping the MAC to re-enter this
        // path) is visible to the operator rather than silent.
        context.io.emit(OutputEvent::message(
            "note: migrated a legacy unauthenticated installed-version file to \
             the MAC-authenticated form; subsequent tampering with the recorded \
             release_unix will be detected."
                .to_owned(),
        ));
    }

    let prev_date = format_unix_date(outcome.previous_release_unix);
    let new_date = format_unix_date(outcome.new_release_unix);
    let exec_note = if outcome.binary_marked_executable {
        ""
    } else {
        // Windows path: file isn't chmod'd; operator may need to
        // unblock the.exe via right-click → Properties depending
        // on download source.
        " (note: on Windows the binary is NOT chmod-executable; \
         re-run via the same launcher / unblock the file if SmartScreen flags it)"
    };
    let relocated_note = match &outcome.previous_binary_relocated_to {
        Some(old_path) => format!(
            "\nold binary kept at: {} (deleted automatically on next node startup)",
            old_path.display(),
        ),
        None => String::new(),
    };
    context.io.emit(OutputEvent::message(format!(
        "applied update: {prev_release} → {new_release}\n\
         previous release: {prev_date}\n\
         new release:      {new_date}\n\
         install_path: {install_path}{relocated_note}\n\
         restart the running node to pick up the new binary{exec_note}",
        prev_release = outcome.previous_release_unix,
        new_release = outcome.new_release_unix,
        prev_date = prev_date,
        new_date = new_date,
        install_path = outcome.install_path.display(),
        relocated_note = relocated_note,
        exec_note = exec_note,
    )));
    Ok(())
}

fn map_checker_err(e: CheckerError) -> veil_cfg::ConfigError {
    match e {
        CheckerError::NotConfigured => veil_cfg::ConfigError::CommandFailed(
            "checker reported NotConfigured despite is_check_enabled() — \
             likely a missing field bypassed validation"
                .to_owned(),
        ),
        CheckerError::InstalledVersion(e) => veil_cfg::ConfigError::CommandFailed(format!(
            "cannot read installed-version state: {e}"
        )),
        CheckerError::Fetch(e) => {
            veil_cfg::ConfigError::CommandFailed(format!("manifest fetch failed: {e}"))
        }
    }
}

fn map_fetch_err(e: FetchError) -> veil_cfg::ConfigError {
    veil_cfg::ConfigError::CommandFailed(format!("binary fetch failed: {e}"))
}

fn map_apply_err(e: ApplyError) -> veil_cfg::ConfigError {
    veil_cfg::ConfigError::CommandFailed(format!("apply failed: {e}"))
}

fn format_unix_date(unix: u64) -> String {
    // Lightweight YYYY-MM-DD formatter — avoids pulling in `chrono`
    // for one date conversion. Computes via days-since-epoch + the
    // fixed Gregorian calendar; works for any Unix timestamp >= 0.
    // (The manifest's release_unix is always >= 0 by validation.)
    let secs = unix as i64;
    let days_since_epoch = secs.div_euclid(86_400);
    // Howard Hinnant's days_from_civil inverse:
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// local `bytes_hex` removed — callers use
// `veil_util::bytes_to_hex` directly.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::{BufferIo, MockConfigOps};
    use std::path::PathBuf;
    use veil_cfg::{Config, UpdateConfig};

    fn ctx_with_config(cfg: Config) -> CommandContext<'static, BufferIo, MockConfigOps> {
        CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: PathBuf::from("/tmp/test-config.toml"),
                raw_config: String::new(),
                loaded_config: cfg,
            },
        }
    }

    #[test]
    fn epic484_3_update_check_cli_rejects_unconfigured() {
        // Default config has [update] disabled — CLI must produce a
        // clear error message guiding the operator to set
        // manifest_urls + expected_issuer_pk, NOT silently exit 0
        // (which would be misclassified as "up to date" by an
        // operator wiring this into a CI gate).
        let context = ctx_with_config(Config::default());
        let args = UpdateArgs {
            command: UpdateCommand::Check,
        };
        let err = handle_update_command(context, args).unwrap_err();
        match err {
            veil_cfg::ConfigError::CommandFailed(msg) => {
                assert!(
                    msg.contains("update.manifest_urls"),
                    "must guide operator to manifest_urls field: {msg}"
                );
                assert!(
                    msg.contains("update.expected_issuer_pk"),
                    "must guide operator to issuer pk field: {msg}"
                );
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn epic484_3_update_apply_cli_rejects_check_only_config() {
        // Operator configured manifest_urls + issuer_pk but neither
        // install_path nor installed_version_path — the check-only
        // mode is fine for `update check` but apply needs both.
        // CLI must reject with clear guidance, NOT silently fail or
        // (worse) write the binary to a default path that may be
        // wrong.
        let cfg = Config {
            update: UpdateConfig {
                manifest_urls: vec!["https://m.example/m".to_owned()],
                expected_issuer_pk: Some("0".repeat(64)),
                installed_version_path: None,
                install_path: None,
                check_interval_secs: None,
            },
            ..Config::default()
        };
        let context = ctx_with_config(cfg);
        let args = UpdateArgs {
            command: UpdateCommand::Apply {
                allow_legacy_state_migration: false,
            },
        };
        let err = handle_update_command(context, args).unwrap_err();
        match err {
            veil_cfg::ConfigError::CommandFailed(msg) => {
                assert!(
                    msg.contains("install_path"),
                    "must guide operator to install_path field: {msg}"
                );
                assert!(
                    msg.contains("installed_version_path"),
                    "must guide operator to installed_version_path field: {msg}"
                );
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn epic484_3_update_apply_cli_rejects_default_config_with_check_guidance() {
        // Default config — no [update] at all. Must surface the
        // same guidance as `update check` since BOTH need
        // is_check_enabled.
        let context = ctx_with_config(Config::default());
        let args = UpdateArgs {
            command: UpdateCommand::Apply {
                allow_legacy_state_migration: false,
            },
        };
        let err = handle_update_command(context, args).unwrap_err();
        let msg = match err {
            veil_cfg::ConfigError::CommandFailed(m) => m,
            other => panic!("expected CommandFailed, got {other:?}"),
        };
        assert!(
            msg.contains("manifest_urls"),
            "default-config apply must mention manifest_urls: {msg}"
        );
    }

    #[test]
    fn epic484_3_update_check_cli_surfaces_fetch_error_when_endpoint_unreachable() {
        // Configured update with an unreachable endpoint — the CLI
        // must surface a fetch-failed error (NOT panic, NOT exit 0).
        // Operators on degraded networks need this to be a clean
        // diagnostic, not a silent failure.
        let cfg = Config {
            update: UpdateConfig {
                manifest_urls: vec!["https://nonexistent.invalid/manifest".to_owned()],
                expected_issuer_pk: Some("0".repeat(64)),
                installed_version_path: None,
                check_interval_secs: None,
                install_path: None,
            },
            ..Config::default()
        };
        let context = ctx_with_config(cfg);
        let args = UpdateArgs {
            command: UpdateCommand::Check,
        };
        let err = handle_update_command(context, args).unwrap_err();
        match err {
            veil_cfg::ConfigError::CommandFailed(msg) => {
                assert!(
                    msg.contains("fetch failed"),
                    "must surface 'fetch failed': {msg}"
                );
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn epic484_3_format_unix_date_known_values() {
        // Sanity-check the Hinnant date formula against well-known
        // Unix-epoch dates so we catch off-by-one regressions.
        assert_eq!(format_unix_date(0), "1970-01-01");
        assert_eq!(format_unix_date(86_399), "1970-01-01"); // last sec of day 1
        assert_eq!(format_unix_date(86_400), "1970-01-02");
        // = day 19_723 since epoch = 1_704_067_200 secs.
        assert_eq!(format_unix_date(1_704_067_200), "2024-01-01");
        // = 1_924_905_600.
        assert_eq!(format_unix_date(1_924_905_600), "2030-12-31");
    }

    #[test]
    fn epic484_3_bytes_hex_zero_padded() {
        assert_eq!(veil_util::bytes_to_hex(&[0x0a, 0x1f, 0xff]), "0a1fff");
        assert_eq!(veil_util::bytes_to_hex(&[]), "");
    }

    // ── sign-manifest CLI ───────────────────────────────────────

    fn write_test_identity(dir: &std::path::Path) -> std::path::PathBuf {
        // Generate a fresh Ed25519 keypair for the release-signing key
        // и persist as TOML (same shape as IdentityConfig). Reused
        // across the tests below.
        use base64::Engine;
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let path = dir.join("release-key.toml");
        let toml = format!(
            "[identity]\nalgo = \"ed25519\"\npublic_key = \"{}\"\nprivate_key = \"{}\"\n",
            base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()),
            base64::engine::general_purpose::STANDARD.encode(sk.to_bytes()),
        );
        std::fs::write(&path, toml).unwrap();
        path
    }

    #[test]
    fn epic484_1_sign_manifest_produces_verifiable_blob() {
        use crate::cmd::cli::SignManifestArgs;
        use veil_update::manifest::{decode_manifest, verify_manifest};

        let tmpdir = tempfile::tempdir().unwrap();
        let bin_path = tmpdir.path().join("test-binary");
        std::fs::write(&bin_path, b"binary contents").unwrap();
        let identity_path = write_test_identity(tmpdir.path());
        let manifest_path = tmpdir.path().join("manifest.bin");

        let args = SignManifestArgs {
            binary: bin_path.clone(),
            version: "1.2.3".to_string(),
            min_compatible_version: "1.0.0".to_string(),
            platform_target: "x86_64-unknown-linux-gnu".to_string(),
            binary_urls: vec!["https://example.com/bin".to_string()],
            identity: identity_path.clone(),
            output: Some(manifest_path.clone()),
            release_unix: Some(1_700_000_000),
        };

        let context = ctx_with_config(Config::default());
        let result = handle_update_command(
            context,
            UpdateArgs {
                command: UpdateCommand::SignManifest(args),
            },
        );
        assert!(result.is_ok(), "sign-manifest must succeed: {result:?}");

        // Read manifest bytes back, decode, verify.
        let bytes = std::fs::read(&manifest_path).unwrap();
        let manifest = decode_manifest(&bytes).expect("manifest decodes");
        verify_manifest(&manifest, None, None, None).expect("freshly-signed manifest verifies");

        assert_eq!(manifest.version, "1.2.3");
        assert_eq!(manifest.min_compatible_version, "1.0.0");
        assert_eq!(manifest.platform_target, "x86_64-unknown-linux-gnu");
        assert_eq!(
            manifest.binary_urls,
            vec!["https://example.com/bin".to_string()]
        );
        assert_eq!(manifest.release_unix, 1_700_000_000);

        // SHA-256 of "binary contents" — verifies the helper digested
        // the file correctly.
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"binary contents");
        assert_eq!(manifest.binary_sha256, expected.as_slice());
    }

    #[test]
    fn epic484_1_sign_manifest_deterministic_with_fixed_inputs() {
        // Reproducibility check: same binary contents + same identity
        // + same release_unix должен produce byte-identical manifest.
        // (Signature includes a per-call nonce у Falcon, NOT у Ed25519
        // so this test deliberately uses Ed25519.)
        use crate::cmd::cli::SignManifestArgs;

        let tmpdir = tempfile::tempdir().unwrap();
        let bin_path = tmpdir.path().join("test-binary");
        std::fs::write(&bin_path, b"deterministic input").unwrap();
        let identity_path = write_test_identity(tmpdir.path());

        let make_args = |out: std::path::PathBuf| SignManifestArgs {
            binary: bin_path.clone(),
            version: "1.0.0".to_string(),
            min_compatible_version: "1.0.0".to_string(),
            platform_target: "x86_64-unknown-linux-gnu".to_string(),
            binary_urls: vec!["https://example.com/bin".to_string()],
            identity: identity_path.clone(),
            output: Some(out),
            release_unix: Some(1_700_000_000),
        };

        let m1 = tmpdir.path().join("m1.bin");
        let m2 = tmpdir.path().join("m2.bin");
        let context1 = ctx_with_config(Config::default());
        let context2 = ctx_with_config(Config::default());
        handle_update_command(
            context1,
            UpdateArgs {
                command: UpdateCommand::SignManifest(make_args(m1.clone())),
            },
        )
        .unwrap();
        handle_update_command(
            context2,
            UpdateArgs {
                command: UpdateCommand::SignManifest(make_args(m2.clone())),
            },
        )
        .unwrap();

        let bytes1 = std::fs::read(&m1).unwrap();
        let bytes2 = std::fs::read(&m2).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "sign-manifest must be deterministic — Ed25519 has no nonce, \
             same inputs MUST yield byte-identical output"
        );
    }

    #[test]
    fn epic484_1_sign_manifest_rejects_missing_binary() {
        use crate::cmd::cli::SignManifestArgs;
        let tmpdir = tempfile::tempdir().unwrap();
        let identity_path = write_test_identity(tmpdir.path());
        let args = SignManifestArgs {
            binary: tmpdir.path().join("does-not-exist"),
            version: "1.0.0".to_string(),
            min_compatible_version: "1.0.0".to_string(),
            platform_target: "x86_64-unknown-linux-gnu".to_string(),
            binary_urls: vec!["https://example.com/bin".to_string()],
            identity: identity_path,
            output: Some(tmpdir.path().join("manifest.bin")),
            release_unix: Some(1_700_000_000),
        };
        let context = ctx_with_config(Config::default());
        let err = handle_update_command(
            context,
            UpdateArgs {
                command: UpdateCommand::SignManifest(args),
            },
        )
        .unwrap_err();
        match err {
            veil_cfg::ConfigError::CommandFailed(msg) => {
                assert!(msg.contains("does-not-exist") || msg.contains("open binary"))
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }
}
