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
/// Этап 11 slice 11a/c/d — если the file carries а
/// `# VEIL_CONFIG_SIGNATURE_V1: …` header, the envelope is verified
/// before the underlying TOML is parsed.  Behaviour depends on the
/// post-parse `global.require_signed_config` flag:
///
/// * **Default `false` (phase 1, warn-only)**: signed-but-tampered
///   configs AND unsigned configs both load с а WARN log so operators
///   have а grace window к sign their existing configs.
/// * **`true` (phase 2 — slice 11d)**: loading FAILS с
///   `ConfigError::SignedConfigEnforced` если the load went down either
///   the unsigned-config OR the verify-failed branch.  Operators flip
///   this after every machine в the fleet has been signed AND verified.
pub fn load_config(path: &Path) -> Result<Config> {
    let format = FileFormat::from_path(path)?;
    let content = fs::read_to_string(path)?;
    let (toml_body, sig_status) = preprocess_signed_config(&content, path);
    let parsed = format::backend(format).load(&toml_body)?;
    // Phase-2 enforcement check: if the operator opted in by setting
    // `global.require_signed_config = true`, refuse k load anything but
    // the `Verified` branch.
    if parsed.global.require_signed_config && !matches!(sig_status, SignedConfigStatus::Verified) {
        return Err(crate::ConfigError::CommandFailed(format!(
            "config '{}' requires а valid signature (global.require_signed_config = true) \
             but verification surfaced а non-Verified state ({:?}).  Sign the file via \
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
    let (toml_body, sig_status) = preprocess_signed_config(content, path);
    let parsed = format::backend(FileFormat::Toml).load(&toml_body)?;
    if parsed.global.require_signed_config && !matches!(sig_status, SignedConfigStatus::Verified) {
        return Err(crate::ConfigError::CommandFailed(format!(
            "applied config requires a valid signature (global.require_signed_config = true) \
             but verification surfaced a non-Verified state ({sig_status:?}); sign it via \
             `veil-cli config sign` (set {TRUSTED_CONFIG_ISSUER_PUBKEY_ENV} to pin the issuer)",
        )));
    }
    Ok(parsed)
}

/// Outcome от [`preprocess_signed_config`] что `load_config` uses к
/// gate enforcement.  Stored separately от the returned body string
/// so phase-2 enforcement can refuse к load even after the body parses
/// successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedConfigStatus {
    /// No signature header on the file (tamper protection OFF).
    Unsigned,
    /// Signature header present AND verified successfully.
    Verified,
    /// Signature header present но verification failed (tamper,
    /// stale pin, malformed envelope).
    VerifyFailed,
}

/// Environment variable (Этап 11 slice 11c) что pins the trusted
/// config-issuer pubkey for hard-fail-on-mismatch verification.  When
/// set, signed configs that don't match this key surface а warn-level
/// log via the verify-failed branch (Phase 1 still loads; phase 2's
/// `require_signed_config = true` flag will refuse).  When unset,
/// `preprocess_signed_config` falls back к unpinned mode (envelope
/// integrity only — degraded posture but still better than no
/// verification).
///
/// Choosing env-var over а config field: pinning inside `config.toml`
/// itself is chicken-and-egg — а tampered config could simply remove
/// the pin.  Env vars live в the systemd unit / Docker compose /
/// Kubernetes manifest, separately от the operator's config bytes.
pub const TRUSTED_CONFIG_ISSUER_PUBKEY_ENV: &str = "VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY";

/// Internal: surface the signed-config envelope on load и normalise
/// the body for the TOML parser.  Three branches:
///
/// 1. **No signature header** → warn-level log surfacing the
///    "tamper protection off" state.  Return raw content unchanged.
/// 2. **Signature header + verify Ok** → info-level log с the issuer
///    pubkey fingerprint и issued_at timestamp.  Return the canonical
///    unsigned TOML что the verifier already stripped + trimmed.
/// 3. **Signature header + verify Err** → warn-level log с the
///    structured error и а "loading anyway" disclaimer.  Strip the
///    header lines от the raw content so the TOML still parses;
///    operator sees the warn в logs и can investigate.
///
/// If `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY` env-var is set, verification
/// runs в pinned mode (signature must match the pinned pubkey OR fall
/// к branch 3); otherwise it runs в unpinned mode (envelope integrity
/// only).
fn preprocess_signed_config(content: &str, path: &Path) -> (String, SignedConfigStatus) {
    let pinned = std::env::var(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV).ok();
    preprocess_signed_config_with_pin(content, path, pinned.as_deref())
}

/// Testable inner: same as [`preprocess_signed_config`] but accepts
/// the trusted-issuer pubkey explicitly instead of reading the env-var.
/// Production callers go through the env-var wrapper; tests pass а
/// concrete `Some(pk)` или `None` directly so they don't race on
/// process-global env state.
fn preprocess_signed_config_with_pin(
    content: &str,
    path: &Path,
    pinned: Option<&str>,
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
                 config '{}' has а signature header but verification \
                 failed: {}.  Loading anyway (refusal is opt-in via \
                 а future `require_signed_config = true` global flag). \
                 Investigate immediately — possible tamper или \
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

/// Parse а TOML config string directly без filesystem access.
///
/// Used by runtime config-injection paths (e.g. `admin apply-config`)
/// where the caller hands в the TOML content bytes (typically from а
/// secure storage backend на the messenger side) и does not want
/// the intermediate plaintext к leak к а readable inode.
pub fn parse_toml_str(content: &str) -> Result<Config> {
    format::backend(FileFormat::Toml).load(content)
}

/// Build а **stub** Config с а freshly-generated ephemeral Ed25519
/// identity и empty peer / listen lists.  Used by the `--defer-init`
/// startup mode (`veil-cli node run --defer-init`) so the daemon
/// can boot без а real config and immediately serve `admin apply-config`
/// requests over its admin socket.
///
/// The identity is а fresh keypair с а PoW-mined nonce satisfying
/// `crypto::DEFAULT_POW_DIFFICULTY` — same as а real production identity
/// so the daemon's own validation passes.  Mining takes ~1-5 s on
/// typical hardware (16 bits в test-low-difficulty, 24 bits otherwise).
///
/// The returned config has:
/// * One [identity] block (Ed25519, ephemeral keypair)
/// * Empty `peers`, `listen`, `bootstrap_peers`
/// * Default global / mobile / etc. config blocks
///
/// **Lifecycle**: the caller writes this config к а temp dir и passes
/// the path к `NodeRuntime::start`.  The first `admin apply-config`
/// triggers а full reload, replacing the stub identity with the real
/// one.  The temp dir lives только for the daemon's process lifetime
/// и does not need к be cleaned up explicitly — modern OSes reap
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
            // (the messenger app is не going к answer а tty).
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
pub fn save_config(path: &Path, config: &Config) -> Result<()> {
    let format = FileFormat::from_path(path)?;
    let backend = format::backend(format);
    let content = if path.is_file() && backend.save_strategy() == SaveStrategy::PatchExisting {
        let existing = fs::read_to_string(path)?;
        backend.patch_existing(&existing, config)?
    } else {
        backend.render(config)?
    };
    veil_util::atomic_write(path, content.as_bytes())?;
    Ok(())
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

    // ── Этап 11 slice 11c: env-var pinned-verification path ──────────

    /// Sign а minimal config, then run the inner preprocessor с
    /// pinned-mode set to the correct issuer pubkey → load Ok branch
    /// fires и the body is the canonical unsigned TOML.
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
        );
        assert!(preprocessed.contains("runtime_flavor = \"multi_thread\""));
        assert!(!preprocessed.contains("VEIL_CONFIG_SIGNATURE_V1"));
    }

    /// Pin к а DIFFERENT pubkey: verification surfaces `IssuerMismatch`
    /// и falls к the warn-and-strip degraded branch.  Body still loads
    /// (phase 1 graceful degradation); operator sees the warn в logs.
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
        );
        // Body still loads (phase-1 graceful degradation), but the
        // signature-header lines ара stripped so the TOML parses.
        assert!(preprocessed.contains("runtime_flavor = \"multi_thread\""));
        assert!(!preprocessed.contains("VEIL_CONFIG_SIGNATURE_V1"));
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
        let (preprocessed, _status) =
            preprocess_signed_config_with_pin(&signed, Path::new("/tmp/test-config.toml"), None);
        assert!(preprocessed.contains("runtime_flavor = \"multi_thread\""));
    }

    // ── Этап 11 slice 11d: SignedConfigStatus enum + load enforcement ──

    /// Status enum returned by the inner preprocessor matches the three
    /// post-preprocess branches that `load_config` checks against the
    /// `require_signed_config` flag.
    #[test]
    fn epic11d_signed_status_unsigned_for_plain_toml() {
        let raw = "[global]\nruntime_flavor = \"multi_thread\"\n";
        let (_body, status) =
            preprocess_signed_config_with_pin(raw, Path::new("/tmp/test-config.toml"), None);
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
        );
        assert_eq!(status, SignedConfigStatus::VerifyFailed);
    }

    /// End-to-end enforcement check: write а require_signed_config-true
    /// config that is itself UNSIGNED → `load_config` returns an Err
    /// directing the operator к sign и restart.
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
            msg.contains("requires а valid signature") || msg.contains("Sign the file"),
            "error must direct operator к sign + restart; got: {msg}",
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }

    /// Opposite path: а require_signed_config-true config that IS
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
        // sign но don't pin.  Verified status is still produced.
        let loaded = load_config(&path).expect("signed config must load");
        assert!(loaded.global.require_signed_config);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }
}
