use std::fs;
use std::path::{Path, PathBuf};

use super::{
    Config, FileFormat, Result,
    format::{self, SaveStrategy},
};

/// Create a fresh default config at `path`. When `force = false` and the
/// file already exists, returns [`ConfigError::AlreadyExists`] rather than
/// silently overwriting.
pub fn init_config(path: &Path, force: bool) -> Result<PathBuf> {
    let path = prepare_init_path(path, force)?;
    let config = Config::default();
    save_config(&path, &config)?;
    Ok(path)
}

/// Canonicalise `path` (appending `config.toml` when it is a directory) and
/// enforce the `force`-overwrite check. Separate [`init_config`] so
/// higher-level CLI code can preview the effective path before writing.
pub fn prepare_init_path(path: &Path, force: bool) -> Result<PathBuf> {
    let path = normalize_init_path(path);
    if path.exists() && !force {
        return Err(super::ConfigError::AlreadyExists(
            path.display().to_string(),
        ));
    }
    Ok(path)
}

/// Read and parse a config file, inferring the format from the extension.
///
/// Phase 11 slice 11a/c/d — if the file carries a
/// `# VEIL_CONFIG_SIGNATURE_V1: …` header, the envelope is verified
/// before the underlying TOML is parsed.  Behaviour depends on the
/// post-parse `global.require_signed_config` flag:
///
/// * **Default `false` (phase 1, warn-only)**: signed-but-tampered
///   configs AND unsigned configs both load with a WARN log so operators
///   have a grace window to sign their existing configs.
/// * **`true` (phase 2 — slice 11d)**: loading FAILS with
///   `ConfigError::SignedConfigEnforced` if the load went down either
///   the unsigned-config OR the verify-failed branch.  Operators flip
///   this after every machine in the fleet has been signed AND verified.
pub fn load_config(path: &Path) -> Result<Config> {
    let format = FileFormat::from_path(path)?;
    let content = fs::read_to_string(path)?;
    let (toml_body, sig_status) = preprocess_signed_config(&content, path);
    let parsed = format::backend(format).load(&toml_body)?;
    // Phase-2 enforcement check: enforcement is demanded by EITHER the in-body
    // `global.require_signed_config = true` OR the external, tamper-proof
    // `VEIL_CONFIG_REQUIRE_SIGNED` env-var (F3) — so a config tampered to clear
    // the in-body flag cannot self-disable the signature requirement.
    let require_signed = parsed.global.require_signed_config || external_require_signed_config();
    if require_signed && !matches!(sig_status, SignedConfigStatus::Verified) {
        return Err(crate::ConfigError::CommandFailed(format!(
            "config '{}' requires a valid signature (global.require_signed_config = true) \
             but verification surfaced a non-Verified state ({:?}).  Sign the file via \
             `veil-cli config sign`, ensure {} env-var matches the operator's pubkey \
             if pinning is desired, AND restart.",
            path.display(),
            sig_status,
            TRUSTED_CONFIG_ISSUER_PUBKEY_ENV,
        )));
    }
    Ok(parsed)
}

/// Like [`load_config`] but for config bytes supplied as a STRING — the admin
/// runtime apply-config path (audit U11). Applies the SAME signed-config
/// enforcement as the on-disk loader: when the supplied config sets
/// `global.require_signed_config = true` it must carry a valid (and, if
/// `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY` is set, pinned) signature, else the
/// apply is refused. Without this, `apply-config` bypassed signed-config
/// entirely, and persisting an unsigned config to a `require_signed_config`
/// daemon would refuse to boot on the next start. `path` is used only for the
/// signature-pin lookup + error context (TOML format assumed for the IPC apply).
pub fn load_config_str(content: &str, path: &Path) -> Result<Config> {
    load_config_str_with_policy(content, path, external_require_signed_config())
}

/// `load_config_str` with the external enforcement signal injected explicitly
/// (production goes through the env-var wrapper above; tests pass the bool
/// directly to avoid mutating process-global env state — same pattern as
/// `preprocess_signed_config_with_pin`).
fn load_config_str_with_policy(
    content: &str,
    path: &Path,
    external_require: bool,
) -> Result<Config> {
    let (toml_body, sig_status) = preprocess_signed_config(content, path);
    let parsed = format::backend(FileFormat::Toml).load(&toml_body)?;
    let require_signed = parsed.global.require_signed_config || external_require;
    if require_signed && !matches!(sig_status, SignedConfigStatus::Verified) {
        return Err(crate::ConfigError::CommandFailed(format!(
            "applied config requires a valid signature (global.require_signed_config = true \
             OR {REQUIRE_SIGNED_CONFIG_ENV} set) but verification surfaced a non-Verified \
             state ({sig_status:?}); sign it via `veil-cli config sign` (set \
             {TRUSTED_CONFIG_ISSUER_PUBKEY_ENV} to pin the issuer)",
        )));
    }
    Ok(parsed)
}

/// Outcome from [`preprocess_signed_config`] that `load_config` uses to
/// gate enforcement.  Stored separately from the returned body string
/// so phase-2 enforcement can refuse to load even after the body parses
/// successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedConfigStatus {
    /// No signature header on the file (tamper protection OFF).
    Unsigned,
    /// Signature header present AND verified successfully.
    Verified,
    /// Signature header present but verification failed (tamper,
    /// stale pin, malformed envelope).
    VerifyFailed,
}

/// Environment variable (Phase 11 slice 11c) that pins the trusted
/// config-issuer pubkey for hard-fail-on-mismatch verification.  When
/// set, signed configs that don't match this key surface a warn-level
/// log via the verify-failed branch (Phase 1 still loads; phase 2's
/// `require_signed_config = true` flag will refuse).  When unset,
/// `preprocess_signed_config` falls back to unpinned mode (envelope
/// integrity only — degraded posture but still better than no
/// verification).
///
/// Choosing env-var over a config field: pinning inside `config.toml`
/// itself is chicken-and-egg — a tampered config could simply remove
/// the pin.  Env vars live in the systemd unit / Docker compose /
/// Kubernetes manifest, separately from the operator's config bytes.
pub const TRUSTED_CONFIG_ISSUER_PUBKEY_ENV: &str = "VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY";

/// External, trusted enforcement signal for "config must be signed" (F3).
///
/// `global.require_signed_config` lives inside the config body, which an
/// attacker with config-write access can strip alongside the signature envelope
/// (set it `false`, remove the header → the loader parses the tampered body and
/// never demands a signature). The enforcement DECISION must therefore also be
/// sourceable from OUTSIDE the mutable config — same rationale as the issuer pin
/// above. When this env-var is truthy (`1`/`true`/`yes`, case-insensitive),
/// signed-config enforcement is forced ON regardless of the in-body flag, so a
/// tampered config cannot self-disable the requirement. The in-body flag is
/// retained as a convenience default (and preserves the gradual-rollout grace
/// window); operators who need tamper-proof enforcement set this env-var in
/// their systemd unit / Docker compose / K8s manifest.
pub const REQUIRE_SIGNED_CONFIG_ENV: &str = "VEIL_CONFIG_REQUIRE_SIGNED";

/// `true` iff [`REQUIRE_SIGNED_CONFIG_ENV`] is set to a truthy value.
fn external_require_signed_config() -> bool {
    std::env::var(REQUIRE_SIGNED_CONFIG_ENV)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

/// External, trusted anti-rollback floor for signed configs (F4).
///
/// `issued_at_unix` is cryptographically covered by the signature, but nothing
/// remembers the newest config accepted so far — so an attacker with config
/// write access could replace the current config with an OLDER, still-validly-
/// signed one (a downgrade to a config with weaker settings). This env-var
/// (unix seconds), living OUTSIDE the mutable config like the issuer pin, sets a
/// minimum acceptable `issued_at_unix`: a verified config older than it is
/// rejected as a rollback. Operators bump it when they roll a new signed config.
pub const MIN_ISSUED_AT_CONFIG_ENV: &str = "VEIL_CONFIG_MIN_ISSUED_AT";

/// Operator-asserted anti-rollback floor from [`MIN_ISSUED_AT_CONFIG_ENV`]
/// (`None` if unset or unparseable).
fn external_min_issued_at() -> Option<u64> {
    std::env::var(MIN_ISSUED_AT_CONFIG_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Internal: surface the signed-config envelope on load and normalise
/// the body for the TOML parser.  Three branches:
///
/// 1. **No signature header** → warn-level log surfacing the
///    "tamper protection off" state.  Return raw content unchanged.
/// 2. **Signature header + verify Ok** → info-level log with the issuer
///    pubkey fingerprint and issued_at timestamp.  Return the canonical
///    unsigned TOML that the verifier already stripped + trimmed.
/// 3. **Signature header + verify Err** → warn-level log with the
///    structured error and a "loading anyway" disclaimer.  Strip the
///    header lines from the raw content so the TOML still parses;
///    operator sees the warn in logs and can investigate.
///
/// If `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY` env-var is set, verification
/// runs in pinned mode (signature must match the pinned pubkey OR fall
/// to branch 3); otherwise it runs in unpinned mode (envelope integrity
/// only).
fn preprocess_signed_config(content: &str, path: &Path) -> (String, SignedConfigStatus) {
    let pinned = std::env::var(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV).ok();
    preprocess_signed_config_with_pin(content, path, pinned.as_deref(), external_min_issued_at())
}

/// Testable inner: same as [`preprocess_signed_config`] but accepts
/// the trusted-issuer pubkey and anti-rollback floor explicitly instead of
/// reading the env-vars. Production callers go through the env-var wrapper;
/// tests pass concrete values directly so they don't race on process-global
/// env state.
fn preprocess_signed_config_with_pin(
    content: &str,
    path: &Path,
    pinned: Option<&str>,
    min_issued_at: Option<u64>,
) -> (String, SignedConfigStatus) {
    if !crate::signed_config::has_signature_header(content) {
        log::warn!(
            "veil_cfg.unsigned_config \
             config file '{}' has no signature header; tamper protection \
             is OFF.  Sign the config to enable byte-level integrity \
             verification on load (see docs/en/OPERATIONS.md → \
             Memory locking section for the parallel ops-side hardening \
             story).",
            path.display()
        );
        return (content.to_string(), SignedConfigStatus::Unsigned);
    }
    if pinned.is_some() {
        log::debug!(
            "veil_cfg.signed_config_pinned \
             config '{}' verification pinned via {} env-var; \
             unpinned-mode acceptance disabled",
            path.display(),
            TRUSTED_CONFIG_ISSUER_PUBKEY_ENV,
        );
    }
    match crate::signed_config::verify_signed_config(content, pinned) {
        Ok(verified) => {
            // F4 (anti-rollback): a validly-signed but OLDER-than-floor config is
            // a downgrade attack. Reject it as a verification failure (so the
            // require-signed gate refuses it) rather than accepting the rollback.
            if let Some(floor) = min_issued_at
                && verified.issued_at_unix < floor
            {
                log::warn!(
                    "veil_cfg.signed_config_rollback \
                     config '{}' issued_at={} is older than {}={} — rejecting as \
                     a rollback (downgrade attack or stale floor).",
                    path.display(),
                    verified.issued_at_unix,
                    MIN_ISSUED_AT_CONFIG_ENV,
                    floor,
                );
                let stripped = content
                    .lines()
                    .filter(|l| !l.starts_with(crate::signed_config::SIGNED_CONFIG_HEADER_PREFIX))
                    .collect::<Vec<_>>()
                    .join("\n");
                return (stripped, SignedConfigStatus::VerifyFailed);
            }
            let fp_len = 16.min(verified.issuer_pk.len());
            log::info!(
                "veil_cfg.signed_config \
                 config '{}' signature verified (issuer={}…, issued_at={}, \
                 pinned={})",
                path.display(),
                &verified.issuer_pk[..fp_len],
                verified.issued_at_unix,
                pinned.is_some(),
            );
            (verified.unsigned_toml, SignedConfigStatus::Verified)
        }
        Err(e) => {
            log::warn!(
                "veil_cfg.signed_config_verify_failed \
                 config '{}' has a signature header but verification \
                 failed: {}.  Loading anyway (refusal is opt-in via \
                 a future `require_signed_config = true` global flag). \
                 Investigate immediately — possible tamper or \
                 stale {} env-var pin.",
                path.display(),
                e,
                TRUSTED_CONFIG_ISSUER_PUBKEY_ENV,
            );
            let stripped = content
                .lines()
                .filter(|l| !l.starts_with(crate::signed_config::SIGNED_CONFIG_HEADER_PREFIX))
                .collect::<Vec<_>>()
                .join("\n");
            (stripped, SignedConfigStatus::VerifyFailed)
        }
    }
}

/// Parse a TOML config string directly without filesystem access.
///
/// Used by runtime config-injection paths (e.g. `admin apply-config`)
/// where the caller hands in the TOML content bytes (typically from a
/// secure storage backend on the messenger side) and does not want
/// the intermediate plaintext to leak to a readable inode.
pub fn parse_toml_str(content: &str) -> Result<Config> {
    format::backend(FileFormat::Toml).load(content)
}

/// Build a **stub** Config with a freshly-generated ephemeral Ed25519
/// identity and empty peer / listen lists.  Used by the `--defer-init`
/// startup mode (`veil-cli node run --defer-init`) so the daemon
/// can boot without a real config and immediately serve `admin apply-config`
/// requests over its admin socket.
///
/// The identity is a fresh keypair with a PoW-mined nonce satisfying
/// `crypto::DEFAULT_POW_DIFFICULTY` — same as a real production identity
/// so the daemon's own validation passes.  Mining takes ~1-5 s on
/// typical hardware (16 bits in test-low-difficulty, 24 bits otherwise).
///
/// The returned config has:
/// * One [identity] block (Ed25519, ephemeral keypair)
/// * Empty `peers`, `listen`, `bootstrap_peers`
/// * Default global / mobile / etc. config blocks
///
/// **Lifecycle**: the caller writes this config to a temp dir and passes
/// the path to `NodeRuntime::start`.  The first `admin apply-config`
/// triggers a full reload, replacing the stub identity with the real
/// one.  The temp dir lives only for the daemon's process lifetime
/// and does not need to be cleaned up explicitly — modern OSes reap
/// `$TMPDIR` on reboot.
pub fn build_stub_config_with_ephemeral_identity() -> Result<Config> {
    use crate::model::{IdentityConfig, SignatureAlgorithm};
    use veil_crypto as crypto;

    let keypair = crypto::generate_keypair(SignatureAlgorithm::Ed25519);
    let pow = crypto::search_nonce(crypto::PowParams {
        algo: SignatureAlgorithm::Ed25519,
        public_key: crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.public_key.clone(),
        )
        .map_err(|e| super::ConfigError::ValidationFailed(format!("stub pk: {e}")))?,
        private_key: crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.private_key.clone(),
        )
        .map_err(|e| super::ConfigError::ValidationFailed(format!("stub sk: {e}")))?,
        target_zero_bits: crypto::DEFAULT_POW_DIFFICULTY,
        timeout: std::time::Duration::from_secs(60),
        start_from: crypto::Base64Nonce::zero(),
        threads: crypto::available_thread_count(),
        progress: None,
    })
    .map_err(|e| super::ConfigError::ValidationFailed(format!("stub pow search: {e}")))?;
    if pow.stop_reason != crypto::PowStopReason::Found {
        return Err(super::ConfigError::ValidationFailed(format!(
            "stub PoW search did not converge (best={} bits, reason={:?})",
            pow.best_zero_bits, pow.stop_reason
        )));
    }
    // node_id MUST equal blake3(public_key) per structural validation
    // rule `identity_node_id_matches_public_key` — pre-compute or
    // validation rejects the stub.
    let derived_node_id =
        crate::model::NodeId::from_public_key(SignatureAlgorithm::Ed25519, &keypair.public_key)
            .map_err(|e| {
                super::ConfigError::ValidationFailed(format!("derive stub node_id: {e}"))
            })?;

    let config = Config {
        identity: Some(IdentityConfig {
            algo: SignatureAlgorithm::Ed25519,
            role: Default::default(),
            public_key: keypair.public_key,
            private_key: keypair.private_key,
            nonce: pow.best_nonce.into_inner(),
            node_id: Some(derived_node_id),
            key_passphrase: None,
            key_passphrase_file: None,
            // Don't prompt — stub mode is non-interactive by definition
            // (the messenger app is not going to answer a tty).
            key_passphrase_prompt: false,
            // Don't burn CPU on background nonce-mining for the stub
            // identity — it will be replaced almost immediately by the
            // first ApplyConfig.
            lazy_mining: false,
            max_lazy_difficulty: 0,
        }),
        ..Config::default()
    };
    Ok(config)
}

/// Serialise `config` back to `path`. For TOML the existing file (if any)
/// is patched in place to preserve user comments and field ordering; JSON
/// backends always render the full document.
///
/// uses [`veil_util::atomic_write`] so a crash mid-write
/// leaves either the old config or the new one, never truncated garbage
/// that would prevent the node from starting.
/// Write `config` to `path` as a FRESH, fully-rendered document — never the
/// comment-preserving `patch_existing` path, even when the file already exists.
///
/// `save_config` patches an existing file in place, but `patch_existing` only
/// rewrites the sections it hand-maintains (global / transport sub-tables /
/// identity / ipc / peers / listen / metrics / bootstrap) — it does NOT emit
/// `[mesh]` / `[mobile]` / `[session]` / `[abuse]` or transport scalars like
/// `default_sni`. So patching over an existing file SILENTLY DROPS any
/// profile-specific section an authoritative full-config writer set in memory
/// (audit cycle-10). `init --force` is exactly such a writer: it builds a
/// complete `Config` from defaults + identity + `apply_profile_defaults`, so it
/// must render the whole struct, not patch the file it is overwriting.
pub fn render_config(path: &Path, config: &Config) -> Result<()> {
    let format = FileFormat::from_path(path)?;
    let backend = format::backend(format);
    let content = backend.render(config)?;
    veil_util::atomic_write(path, content.as_bytes())?;
    Ok(())
}

/// Render `config` to its serialized TOML form **without touching the
/// filesystem**. For callers that need the config bytes in memory rather than
/// on disk — e.g. the embedded-node FFI returning a freshly provisioned
/// identity so a host app can store it inside its own (deniable) container
/// instead of a plaintext `config.toml`.
pub fn render_config_to_string(config: &Config) -> Result<String> {
    format::backend(FileFormat::Toml).render(config)
}

pub fn save_config(path: &Path, config: &Config) -> Result<()> {
    let format = FileFormat::from_path(path)?;
    let backend = format::backend(format);
    let content = if path.is_file() && backend.save_strategy() == SaveStrategy::PatchExisting {
        let existing = fs::read_to_string(path)?;
        let patched = backend.patch_existing(&existing, config)?;
        // audit cycle-8 H4: `patch_existing` preserves the file's leading
        // comments — including a `# VEIL_CONFIG_SIGNATURE_V1:` header — verbatim
        // over the now-MUTATED body. The retained signature no longer matches
        // the new bytes, so the next `load_config` gets `VerifyFailed` (a WARN
        // in phase-1, but a HARD boot refusal under `require_signed_config` /
        // `VEIL_CONFIG_REQUIRE_SIGNED`). Rather than silently leave a config
        // that won't verify, strip the now-stale header and warn the operator
        // to re-sign.
        if crate::signed_config::has_signature_header(&patched) {
            log::warn!(
                "config at {} was signed; saving changes INVALIDATED the signature — \
                 stripped the now-stale signature header. Re-run `config sign` to re-sign \
                 before relying on require_signed_config enforcement.",
                path.display()
            );
            crate::signed_config::strip_signature_headers(&patched)
        } else {
            patched
        }
    } else {
        backend.render(config)?
    };
    veil_util::atomic_write(path, content.as_bytes())?;
    Ok(())
}

/// Process-wide guard serializing config read-modify-write sequences
/// (audit cycle-8 H5).
///
/// `save_config` re-reads + patches the file from the passed `Config`, so a
/// caller doing `load_config → mutate one field → save_config` must hold this
/// guard across the WHOLE sequence. Otherwise two concurrent RMW callers — e.g.
/// the lazy-miner identity-nonce upgrade and a per-peer nonce persist — each
/// load the same baseline and the last `save_config` clobbers the other's field
/// (last-writer-wins), silently losing a persisted nonce. There is exactly one
/// config file per process, so a single global lock is sufficient. Poison is
/// recovered (a panic mid-write must not wedge all future writers).
pub fn config_write_guard() -> std::sync::MutexGuard<'static, ()> {
    static CONFIG_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    CONFIG_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Read the raw on-disk bytes of a config file without parsing them —
/// used by tooling that inspects the source text (e.g. diff against patched
/// output) rather than the decoded model.
pub fn read_raw_config(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?)
}

fn normalize_init_path(path: &Path) -> PathBuf {
    if path.is_dir() || path.extension().is_none() {
        path.join("config.toml")
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn normalizes_directory_path() {
        let path = normalize_init_path(Path::new("/tmp/veil"));
        assert_eq!(path, PathBuf::from("/tmp/veil/config.toml"));
    }

    #[test]
    fn init_config_refuses_to_overwrite_without_force() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("veil-init-test-{unique}"));
        let path = root.join("config.toml");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(&path, "[global]\n").expect("seed config");

        let err = init_config(&path, false).expect_err("must reject overwrite");
        match err {
            super::super::ConfigError::AlreadyExists(existing) => {
                assert_eq!(existing, path.display().to_string());
            }
            other => panic!("unexpected error: {other}"),
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }

    /// cycle-10 regression: `render_config` over an EXISTING file emits a
    /// fully-rendered document, preserving profile-set fields that the
    /// `save_config` patch path silently drops (here `transport.default_sni`,
    /// a transport scalar `patch_existing`/`set_transport` does not write).
    /// This is the mechanism behind `init --force` losing a profile's
    /// anti-censorship defaults; `init` now renders instead of patching.
    #[test]
    fn render_config_over_existing_file_preserves_profile_scalars() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("veil-render-init-test-{unique}"));
        let path = root.join("config.toml");
        fs::create_dir_all(&root).expect("create temp dir");
        // Pre-existing file WITHOUT default_sni (as a prior `init` would leave).
        fs::write(&path, "[global]\nruntime_flavor = \"multi_thread\"\n").expect("seed config");

        let mut config = Config::default();
        config.transport.default_sni = Some("www.example.com".into());

        // Patch path drops the transport scalar...
        save_config(&path, &config).expect("patch save");
        let patched = load_config(&path).expect("reload patched");
        assert_eq!(
            patched.transport.default_sni, None,
            "patch_existing drops transport.default_sni (the bug)",
        );

        // ...render path keeps it.
        render_config(&path, &config).expect("render save");
        let rendered = load_config(&path).expect("reload rendered");
        assert_eq!(
            rendered.transport.default_sni,
            Some("www.example.com".into()),
            "render_config must preserve the profile-set default_sni",
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn prepare_init_path_refuses_to_overwrite_without_force() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("veil-prepare-init-test-{unique}"));
        let path = root.join("config.toml");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(&path, "[global]\n").expect("seed config");

        let err = prepare_init_path(&path, false).expect_err("must reject overwrite");
        match err {
            super::super::ConfigError::AlreadyExists(existing) => {
                assert_eq!(existing, path.display().to_string());
            }
            other => panic!("unexpected error: {other}"),
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }

    // ── Phase 11 slice 11c: env-var pinned-verification path ──────────

    /// Sign a minimal config, then run the inner preprocessor with
    /// pinned-mode set to the correct issuer pubkey → load Ok branch
    /// fires and the body is the canonical unsigned TOML.
    #[test]
    fn epic11c_preprocess_with_pin_accepts_matching_issuer() {
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");
        let (preprocessed, _status) = preprocess_signed_config_with_pin(
            &signed,
            Path::new("/tmp/test-config.toml"),
            Some(&kp.public_key),
            None,
        );
        assert!(preprocessed.contains("runtime_flavor = \"multi_thread\""));
        assert!(!preprocessed.contains("VEIL_CONFIG_SIGNATURE_V1"));
    }

    /// audit cycle-8 H4: saving (patching) a signed config must STRIP the now-
    /// stale signature header instead of leaving it over the mutated body
    /// (which would fail verification / refuse boot under enforcement).
    #[test]
    fn save_config_strips_stale_signature_header_h4() {
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");
        assert!(signed.contains("VEIL_CONFIG_SIGNATURE_V1"));

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("veil-h4-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, &signed).unwrap();

        // Mutate + save → must strip the now-stale signature header.
        save_config(&path, &Config::default()).expect("save");

        let after = fs::read_to_string(&path).unwrap();
        assert!(
            !after.contains("VEIL_CONFIG_SIGNATURE_V1"),
            "save_config must strip the stale signature header, got:\n{after}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// audit cycle-8 H5: the config-write guard must serialize a read-modify-
    /// write so two concurrent callers don't lose updates. Models the
    /// `load → mutate → save` the lazy-miner and peer-handshake persists do with
    /// a deliberately racy load-then-store on a shared counter — correct (no
    /// lost updates) ONLY if the guard provides mutual exclusion across the RMW.
    #[test]
    fn config_write_guard_serializes_read_modify_write_h5() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SHARED: AtomicU64 = AtomicU64::new(0);
        SHARED.store(0, Ordering::SeqCst);
        let iters = 5_000u64;
        let spawn_worker = || {
            std::thread::spawn(move || {
                for _ in 0..iters {
                    let _g = config_write_guard();
                    let v = SHARED.load(Ordering::SeqCst);
                    SHARED.store(v + 1, Ordering::SeqCst); // racy without the guard
                }
            })
        };
        let t1 = spawn_worker();
        let t2 = spawn_worker();
        t1.join().unwrap();
        t2.join().unwrap();
        assert_eq!(
            SHARED.load(Ordering::SeqCst),
            2 * iters,
            "config_write_guard must serialize read-modify-write (no lost updates)"
        );
    }

    /// Pin to a DIFFERENT pubkey: verification surfaces `IssuerMismatch`
    /// and falls to the warn-and-strip degraded branch.  Body still loads
    /// (phase 1 graceful degradation); operator sees the warn in logs.
    #[test]
    fn epic11c_preprocess_with_pin_falls_back_on_mismatch() {
        let kp_a = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let kp_b = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp_a.public_key,
            &kp_a.private_key,
            kp_a.algo,
            1_700_000_000,
        )
        .expect("sign with kp_a");
        let (preprocessed, _status) = preprocess_signed_config_with_pin(
            &signed,
            Path::new("/tmp/test-config.toml"),
            Some(&kp_b.public_key), // wrong pin
            None,
        );
        // Body still loads (phase-1 graceful degradation), but the
        // signature-header lines are stripped so the TOML parses.
        assert!(preprocessed.contains("runtime_flavor = \"multi_thread\""));
        assert!(!preprocessed.contains("VEIL_CONFIG_SIGNATURE_V1"));
    }

    /// F3: an UNSIGNED config with no in-body `require_signed_config` must load
    /// when no external enforcement is set (grace window), but MUST be refused
    /// when the external `VEIL_CONFIG_REQUIRE_SIGNED` signal is on — even though
    /// the (attacker-mutable) in-body flag is absent/false. This is the bypass
    /// the in-config-only flag could not close.
    #[test]
    fn f3_external_require_signed_enforces_on_unsigned_config() {
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n"; // unsigned, no flag
        let path = Path::new("/tmp/f3-config.toml");
        // No external enforcement → loads (phase-1 grace).
        assert!(
            load_config_str_with_policy(raw, path, false).is_ok(),
            "unsigned config must load when neither in-body flag nor env demands signing"
        );
        // External enforcement ON → refused despite the absent in-body flag.
        let err = load_config_str_with_policy(raw, path, true)
            .expect_err("external require-signed must refuse an unsigned config");
        let msg = format!("{err}");
        assert!(
            msg.contains("requires a valid signature"),
            "unexpected error: {msg}"
        );
    }

    /// F3 regression: the in-body flag still enforces on its own (external off).
    #[test]
    fn f3_in_body_require_signed_still_enforced() {
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\nrequire_signed_config = true\n";
        let path = Path::new("/tmp/f3-config2.toml");
        assert!(
            load_config_str_with_policy(raw, path, false).is_err(),
            "in-body require_signed_config=true must still refuse an unsigned config"
        );
    }

    /// F4: a validly-signed config OLDER than the anti-rollback floor is rejected
    /// (VerifyFailed), while one at/above the floor — or with no floor — verifies.
    #[test]
    fn f4_anti_rollback_floor_rejects_older_signed_config() {
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_000, // issued_at_unix
        )
        .expect("sign");
        let path = Path::new("/tmp/f4-config.toml");
        // floor below issued_at → accepted.
        let (_b, st) =
            preprocess_signed_config_with_pin(&signed, path, Some(&kp.public_key), Some(500));
        assert_eq!(
            st,
            SignedConfigStatus::Verified,
            "newer-than-floor must verify"
        );
        // floor above issued_at → rollback rejected.
        let (_b2, st2) =
            preprocess_signed_config_with_pin(&signed, path, Some(&kp.public_key), Some(2_000));
        assert_eq!(
            st2,
            SignedConfigStatus::VerifyFailed,
            "older-than-floor must be rejected as a rollback"
        );
        // no floor → accepted (back-compat).
        let (_b3, st3) =
            preprocess_signed_config_with_pin(&signed, path, Some(&kp.public_key), None);
        assert_eq!(st3, SignedConfigStatus::Verified, "no floor must verify");
    }

    /// Unpinned mode (`None`) accepts any internally-consistent envelope,
    /// matching the slice-11a unpinned path.
    #[test]
    fn epic11c_preprocess_without_pin_accepts_any_consistent_issuer() {
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");
        let (preprocessed, _status) = preprocess_signed_config_with_pin(
            &signed,
            Path::new("/tmp/test-config.toml"),
            None,
            None,
        );
        assert!(preprocessed.contains("runtime_flavor = \"multi_thread\""));
    }

    // ── Phase 11 slice 11d: SignedConfigStatus enum + load enforcement ──

    /// Status enum returned by the inner preprocessor matches the three
    /// post-preprocess branches that `load_config` checks against the
    /// `require_signed_config` flag.
    #[test]
    fn epic11d_signed_status_unsigned_for_plain_toml() {
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let (_body, status) =
            preprocess_signed_config_with_pin(raw, Path::new("/tmp/test-config.toml"), None, None);
        assert_eq!(status, SignedConfigStatus::Unsigned);
    }

    #[test]
    fn epic11d_signed_status_verified_for_good_signature() {
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");
        let (_body, status) = preprocess_signed_config_with_pin(
            &signed,
            Path::new("/tmp/test-config.toml"),
            Some(&kp.public_key),
            None,
        );
        assert_eq!(status, SignedConfigStatus::Verified);
    }

    #[test]
    fn epic11d_signed_status_verify_failed_on_wrong_pin() {
        let kp_a = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let kp_b = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let signed = crate::signed_config::sign_config(
            raw,
            &kp_a.public_key,
            &kp_a.private_key,
            kp_a.algo,
            1_700_000_000,
        )
        .expect("sign with kp_a");
        let (_body, status) = preprocess_signed_config_with_pin(
            &signed,
            Path::new("/tmp/test-config.toml"),
            Some(&kp_b.public_key),
            None,
        );
        assert_eq!(status, SignedConfigStatus::VerifyFailed);
    }

    /// End-to-end enforcement check: write a require_signed_config-true
    /// config that is itself UNSIGNED → `load_config` returns an Err
    /// directing the operator to sign and restart.
    #[test]
    fn epic11d_require_signed_config_refuses_unsigned_load() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("veil-11d-unsigned-{unique}"));
        let path = root.join("config.toml");
        fs::create_dir_all(&root).expect("create temp dir");
        // Minimal valid TOML c require_signed_config = true.  Note: NO
        // signature header — that's the whole point of the test.
        let raw = "[global]\nrequire_signed_config = true\n";
        fs::write(&path, raw).expect("seed config");

        let err = load_config(&path).expect_err("must refuse unsigned config");
        let msg = format!("{err}");
        assert!(
            msg.contains("requires a valid signature") || msg.contains("Sign the file"),
            "error must direct operator to sign + restart; got: {msg}",
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }

    /// Opposite path: a require_signed_config-true config that IS
    /// properly signed loads cleanly.
    #[test]
    fn epic11d_require_signed_config_accepts_properly_signed_load() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("veil-11d-signed-{unique}"));
        let path = root.join("config.toml");
        fs::create_dir_all(&root).expect("create temp dir");
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let raw = format!(
            "[global]\nrequire_signed_config = true\n\n\
             [identity]\nalgo = \"ed25519\"\n\
             public_key = \"{}\"\nprivate_key = \"{}\"\n\
             nonce = \"AAAAAA==\"\n",
            kp.public_key, kp.private_key,
        );
        let signed = crate::signed_config::sign_config(
            &raw,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");
        fs::write(&path, &signed).expect("seed signed config");

        // Note: load_config reads VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY
        // env-var.  We don't set it here so verification runs unpinned —
        // matches the production deployment mode where some operators
        // sign but don't pin.  Verified status is still produced.
        let loaded = load_config(&path).expect("signed config must load");
        assert!(loaded.global.require_signed_config);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }
}
