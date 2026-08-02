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
    let pinned = std::env::var(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV).ok();
    load_config_with_policy(path, pinned.as_deref(), external_require_signed_config())
}

/// `load_config` with the two external signals injected explicitly.
///
/// Production goes through the env-var wrapper above; tests pass concrete
/// values so they don't mutate process-global env state (same pattern as
/// `load_config_str_with_policy`).
fn load_config_with_policy(
    path: &Path,
    pinned: Option<&str>,
    external_require: bool,
) -> Result<Config> {
    let format = FileFormat::from_path(path)?;
    let content = fs::read_to_string(path)?;
    let (toml_body, sig_status) =
        preprocess_signed_config_with_pin(&content, path, pinned, external_min_issued_at());
    let mut parsed = format::backend(format).load(&toml_body)?;
    // Phase-2 enforcement check: enforcement is demanded by EITHER the in-body
    // `global.require_signed_config = true` OR the external, tamper-proof
    // `VEIL_CONFIG_REQUIRE_SIGNED` env-var (F3) — so a config tampered to clear
    // the in-body flag cannot self-disable the signature requirement.
    let require_signed = parsed.global.require_signed_config || external_require;
    enforce_signed_config(
        require_signed,
        pinned,
        &sig_status,
        &format!("config '{}'", path.display()),
    )?;
    // Learned state (identity PoW nonce, per-peer nonces) lives in a sidecar,
    // NOT in the signed bytes — see `runtime_state`. Overlaid here, after
    // verification, so what got verified is exactly what the operator signed.
    crate::runtime_state::apply(&mut parsed, &crate::runtime_state::load(path));
    Ok(parsed)
}

/// The signed-config gate, in one place for both loaders.
///
/// Two refusals, and the second is the one the audit found missing.
///
/// 1. Enforcement is on and the file did not verify — the original check.
/// 2. Enforcement is on and NO issuer is pinned. Without a pin, "verified"
///    means only "somebody signed this", and the signing key an attacker
///    reaches for is the node's own `[identity].private_key`, which sits in
///    the very file they just rewrote. Self-certification is not
///    authentication, so an unpinned enforced config was enforcing nothing
///    while reporting that it was. Fail closed and say which env-var is
///    missing.
///
/// This does NOT make a pin a precondition for starting a node: enforcement
/// is opt-in, and a node with neither the flag nor the env-var set boots
/// unsigned exactly as before. It only refuses the combination that claims a
/// guarantee it does not have.
fn enforce_signed_config(
    require_signed: bool,
    pinned: Option<&str>,
    sig_status: &SignedConfigStatus,
    subject: &str,
) -> Result<()> {
    if !require_signed {
        return Ok(());
    }
    if pinned.is_none_or(str::is_empty) {
        return Err(crate::ConfigError::CommandFailed(format!(
            "{subject} demands a signed config but no issuer is pinned. An unpinned \
             signature only proves that SOMEONE signed the file — including whoever \
             rewrote it, using the `[identity].private_key` stored in that same file. \
             Set {TRUSTED_CONFIG_ISSUER_PUBKEY_ENV} to the offline signer's public key \
             (in the systemd unit / compose file, NOT in the config), or clear the \
             enforcement flag and {REQUIRE_SIGNED_CONFIG_ENV}."
        )));
    }
    if !matches!(sig_status, SignedConfigStatus::Verified) {
        return Err(crate::ConfigError::CommandFailed(format!(
            "{subject} requires a valid signature but verification surfaced a \
             non-Verified state ({sig_status:?}). Re-sign with the pinned offline \
             signer via `veil-cli config sign --signer-key <path>`, confirm \
             {TRUSTED_CONFIG_ISSUER_PUBKEY_ENV} matches it, AND restart."
        )));
    }
    Ok(())
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
    let pinned = std::env::var(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV).ok();
    load_config_str_with_policy(
        content,
        path,
        external_require_signed_config(),
        pinned.as_deref(),
    )
}

/// `load_config_str` with the external enforcement signal injected explicitly
/// (production goes through the env-var wrapper above; tests pass the bool
/// directly to avoid mutating process-global env state — same pattern as
/// `preprocess_signed_config_with_pin`).
fn load_config_str_with_policy(
    content: &str,
    path: &Path,
    external_require: bool,
    pinned: Option<&str>,
) -> Result<Config> {
    let (toml_body, sig_status) =
        preprocess_signed_config_with_pin(content, path, pinned, external_min_issued_at());
    let parsed = format::backend(FileFormat::Toml).load(&toml_body)?;
    let require_signed = parsed.global.require_signed_config || external_require;
    enforce_signed_config(require_signed, pinned, &sig_status, "the applied config")?;
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
/// (Both loaders now read the pin themselves so they can pass it to
/// [`enforce_signed_config`] as well; the old env-reading wrapper would have
/// read it twice and could not have told the gate what it found.)
fn _preprocess_signed_config_doc_anchor() {}

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
/// The stub ALWAYS boots with `receive_anonymous = true` (plain rendezvous
/// RECEIVE = reachability: register a subscriber at a relay so it forwards
/// introduces to us — needed for ANY NAT'd node, anonymous or not; without it
/// the node publishes a rendezvous ad but services no introduces). When
/// `anonymous`, it ADDITIONALLY arms `onion_service` (location anonymity). This
/// matters for deferred-init: the anonymity x25519 key + onion-publish task are
/// created ONCE at boot from this config and are NOT re-applied on the later
/// identity-promoting apply-config (reload freezes `[anonymity]` by design).
/// The published blinded descriptor,
/// however, is sealed against the LIVE identity at publish time, so once the
/// real identity is applied the descriptor resolves to it — booting the stub
/// "anonymous" is therefore the way to make a deferred node actually onion-
/// reachable. The throwaway stub identity is never published (publish is
/// periodic, not at boot, and the identity is replaced within seconds).
pub fn build_stub_config_with_ephemeral_identity(anonymous: bool) -> Result<Config> {
    use crate::model::{IdentityConfig, SignatureAlgorithm};

    // A FIXED, pre-mined throwaway identity (valid canonical-difficulty PoW),
    // used ONLY to satisfy the config schema + boot validation in deferred-init
    // mode. The node binds NO listeners under it and replaces it via the first
    // apply-config BEFORE any traffic, so a shared constant is safe — and it
    // avoids a per-boot PoW search that, at the canonical difficulty, can miss
    // its timeout on slow hardware and fail the boot outright. (Generated once
    // via `veil_config_init`; see the deferred path in veilclient-ffi.)
    const STUB_PUBLIC_KEY: &str = "Owg2N56YdWIRcQCM2cQPBT1qUurTcE/tQ2njCiBW6Q8=";
    const STUB_PRIVATE_KEY: &str = "q9j8l7T6NRwquBdwz0WvwqWZthOySfgFVs+CRx78EbI=";
    const STUB_NONCE: &str = "AenuSA==";

    // node_id MUST equal blake3(public_key) per the structural validation rule
    // `identity_node_id_matches_public_key` — derive it from the fixed key.
    let node_id =
        crate::model::NodeId::from_public_key(SignatureAlgorithm::Ed25519, STUB_PUBLIC_KEY)
            .map_err(|e| {
                super::ConfigError::ValidationFailed(format!("derive stub node_id: {e}"))
            })?;

    let mut config = Config {
        identity: Some(IdentityConfig {
            algo: SignatureAlgorithm::Ed25519,
            role: Default::default(),
            public_key: STUB_PUBLIC_KEY.to_owned(),
            private_key: STUB_PRIVATE_KEY.to_owned(),
            nonce: STUB_NONCE.to_owned(),
            node_id: Some(node_id),
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
    // The deferred stub is ALWAYS an ephemeral node (its identity is replaced by
    // the first apply-config, and the host app keeps no config.toml on disk).
    // Turn off ALL on-disk persistence: persist tasks are spawned once at boot
    // from this config (a later reload won't add them), and for an embedded
    // deniable node writing snapshots — DHT values, RTT/Vivaldi/gateway tables,
    // peer pubkeys, discovered-peer cache — to veil's working dir is both a
    // deniability leak (network metadata in cleartext outside the container) and
    // the source of the recurring `dht.values.persist.flush_err` warning (the
    // default snapshot path doesn't exist on the deferred path). Nothing the
    // messenger needs depends on it: it bootstraps via invites + live sessions.
    config.persist_enabled = false;
    // The `[identity]` above is a compiled-in constant, so ANY key derived from
    // it is derivable by anyone with the source. Mark it, and let the runtime
    // refuse to build long-lived identity-bound material out of it — see
    // `Config::ephemeral_identity`.
    config.ephemeral_identity = true;
    // `receive_anonymous` = plain rendezvous RECEIVE = REACHABILITY, NOT
    // anonymity. It runs `spawn_rendezvous_recipient_task`, which registers a
    // subscriber at a relay (over our DIRECT node_id-keyed session) so the relay
    // forwards introduces addressed to our deterministic cookie. The relay
    // learns nothing new — our node_id already keys the sovereign-signed ad we
    // publish unconditionally. Without it a NAT'd node publishes that ad but
    // registers NO subscriber, so the relay drops every introduce with
    // `cookie_unknown` and the node is unreachable. So enable it ALWAYS — a
    // non-anonymous NAT'd receiver needs it just as much as an anonymous one.
    // It also mints the device x25519 key via the boot gate
    // (`relay_capable || receive_anonymous || onion_service`), needed to unseal
    // introduces. `relay_capable` stays false (we don't carry others' circuits).
    config.anonymity.receive_anonymous = true;
    if anonymous {
        // LOCATION anonymity (opt-in): additionally run the onion service so
        // peers/relays never learn this identity's IP and it can't be correlated
        // to the user's other identities. Independent of reachability above.
        config.anonymity.onion_service = true;
    }
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
            // Stripping is only tolerable while enforcement is OFF (the phase-1
            // grace window): the operator gets a warning and a config that still
            // loads. Under enforcement the same strip is a self-brick — the next
            // boot refuses a config the daemon itself unsigned — so refuse the
            // WRITE instead of the boot. Nothing legitimate is lost: the node's
            // own mutable state moved to the `runtime_state` sidecar, and an
            // operator edit under enforcement has to go back through the offline
            // signer anyway.
            if config.global.require_signed_config || external_require_signed_config() {
                return Err(crate::ConfigError::CommandFailed(format!(
                    "refusing to rewrite the signed config at {}: this write cannot \
                     reproduce the signature, and enforcement is ON \
                     (global.require_signed_config or {REQUIRE_SIGNED_CONFIG_ENV}), so \
                     stripping it would leave a config the next boot refuses. Edit and \
                     re-sign offline, then deploy the signed file.",
                    path.display()
                )));
            }
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
mod signed_config_gate_tests {
    use super::*;

    /// Audit V-04. Without a pinned issuer, `Verified` means "somebody signed
    /// this" — and the key the attacker reaches for is `[identity].private_key`
    /// sitting in the file they just rewrote. An enforced config with no pin was
    /// therefore enforcing nothing while logging that it was.
    #[test]
    fn enforcement_without_a_pinned_issuer_is_refused() {
        let err = enforce_signed_config(true, None, &SignedConfigStatus::Verified, "cfg")
            .expect_err("a verified-but-unpinned config must not satisfy enforcement");
        let msg = err.to_string();
        assert!(
            msg.contains(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV),
            "the refusal must name the env-var that fixes it: {msg}"
        );
        // An empty pin is an unset pin. `FOO=` in a unit file is a normal way to
        // "clear" a variable, and it must not read as "pinned to the empty key".
        assert!(
            enforce_signed_config(true, Some(""), &SignedConfigStatus::Verified, "cfg").is_err()
        );
    }

    /// The gate must not become "a node needs an operator CA to start" — the
    /// 2026-07-28 decision requires booting with no sovereign identity at all.
    #[test]
    fn an_unenforced_config_still_loads_with_no_pin_and_no_signature() {
        for status in [
            SignedConfigStatus::Unsigned,
            SignedConfigStatus::Verified,
            SignedConfigStatus::VerifyFailed,
        ] {
            assert!(
                enforce_signed_config(false, None, &status, "cfg").is_ok(),
                "enforcement is opt-in; {status:?} must load when it is off"
            );
        }
    }

    #[test]
    fn a_pinned_but_unverified_config_is_still_refused() {
        for status in [
            SignedConfigStatus::Unsigned,
            SignedConfigStatus::VerifyFailed,
        ] {
            assert!(enforce_signed_config(true, Some("PK"), &status, "cfg").is_err());
        }
        assert!(
            enforce_signed_config(true, Some("PK"), &SignedConfigStatus::Verified, "cfg").is_ok()
        );
    }

    /// Audit V-05. Stripping a signature the writer cannot reproduce is a
    /// self-brick under enforcement: the daemon unsigns its own config and the
    /// next boot refuses it. Refuse the WRITE instead of the boot.
    #[test]
    fn saving_over_a_signed_config_is_refused_under_enforcement() {
        let kp = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        let signed = crate::signed_config::sign_config(
            "[global]\nrequire_signed_config = true\n",
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");

        let dir = std::env::temp_dir().join("veil-v05-save-refusal");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("config.toml");
        fs::write(&path, &signed).expect("seed signed config");

        let mut config = Config::default();
        config.global.require_signed_config = true;
        let err =
            save_config(&path, &config).expect_err("must refuse to unsign an enforced config");
        assert!(
            err.to_string().contains("refusing to rewrite"),
            "unexpected error: {err}"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("read back"),
            signed,
            "the refused write must leave the signed bytes untouched"
        );

        // With enforcement off the phase-1 grace window still applies: strip and
        // warn, so an operator mid-rollout is not blocked.
        config.global.require_signed_config = false;
        fs::write(
            &path,
            crate::signed_config::sign_config(
                "[global]\n",
                &kp.public_key,
                &kp.private_key,
                kp.algo,
                1_700_000_000,
            )
            .expect("sign"),
        )
        .expect("reseed");
        save_config(&path, &config).expect("unenforced save still works");
        assert!(!crate::signed_config::has_signature_header(
            &fs::read_to_string(&path).expect("read back")
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Audit V-03: `config sign` must not sign with the key stored in the file
    /// it is signing. The CLI enforces it; this pins the property the CLI check
    /// relies on — a signer key is a distinct keypair, not a view of the
    /// identity.
    #[test]
    fn a_minted_signer_key_is_not_the_node_identity() {
        let a = crate::signed_config::generate_signer_key(crate::SignatureAlgorithm::Ed25519);
        let b = crate::signed_config::generate_signer_key(crate::SignatureAlgorithm::Ed25519);
        assert_ne!(a.public_key, b.public_key);
        assert!(!a.public_key.is_empty() && !a.private_key.is_empty());
        assert!(
            crate::signed_config::render_signer_key(&a)
                .expect("render")
                .contains(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV),
            "the file must tell the operator what to pin"
        );
    }
}

#[cfg(test)]
mod tests {
    /// The deferred stub MUST mark itself, and the marker must not be
    /// something a config file can set.
    ///
    /// Everything that refuses to derive long-lived key material from the
    /// placeholder hangs off this one flag. If it silently stopped being set,
    /// the node would go back to deriving its mailbox and rendezvous keys from
    /// a constant that ships in the source — and nothing else would look wrong.
    #[test]
    fn the_deferred_stub_marks_its_identity_as_a_placeholder() {
        let stub = super::build_stub_config_with_ephemeral_identity(false).unwrap();
        assert!(stub.ephemeral_identity);
        assert!(!stub.persist_enabled);

        // A real config never carries it, and cannot acquire it from TOML —
        // otherwise editing a file would make a node stop persisting its keys.
        assert!(!super::super::Config::default().ephemeral_identity);
        // Root-level key, BEFORE any table header — putting it under [global]
        // would land it in a different struct and prove nothing.
        let from_disk: super::super::Config =
            toml::from_str("ephemeral_identity = true\n[global]\n").unwrap();
        assert!(
            !from_disk.ephemeral_identity,
            "the marker must not be settable from a config file"
        );
    }

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
            load_config_str_with_policy(raw, path, false, None).is_ok(),
            "unsigned config must load when neither in-body flag nor env demands signing"
        );
        // External enforcement ON → refused despite the absent in-body flag.
        // Pinned, so the refusal is about the missing signature and not about
        // the missing pin (V-04 covers that case separately).
        let err = load_config_str_with_policy(raw, path, true, Some("PINNED-PK"))
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
            load_config_str_with_policy(raw, path, false, Some("PINNED-PK")).is_err(),
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

        let err = load_config_with_policy(&path, Some("PINNED-PK"), false)
            .expect_err("must refuse unsigned config");
        let msg = format!("{err}");
        assert!(
            msg.contains("requires a valid signature") || msg.contains("Re-sign"),
            "error must direct operator to sign + restart; got: {msg}",
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }

    /// Opposite path: a require_signed_config-true config that IS
    /// properly signed loads cleanly — **when the issuer is pinned**.
    ///
    /// The pin is not decoration. This test used to run unpinned, with a
    /// comment calling that "the production deployment mode where some
    /// operators sign but don't pin" — and it passed, because unpinned
    /// verification accepts any self-consistent envelope. The config it signs
    /// with is the one below: `[identity].private_key` is IN the file. So the
    /// old assertion was "a config signed by whoever holds the file is
    /// accepted", which is what audit V-04 named. Pinning is now required for
    /// enforcement, and the unpinned case is asserted to fail.
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

        let loaded = load_config_with_policy(&path, Some(&kp.public_key), false)
            .expect("a signed config from the pinned issuer must load");
        assert!(loaded.global.require_signed_config);

        // Same bytes, same valid signature, no pin — refused. "Verified"
        // without a pin only says the envelope is self-consistent.
        let err = load_config_with_policy(&path, None, false)
            .expect_err("enforcement without a pinned issuer must fail closed");
        assert!(
            err.to_string().contains(TRUSTED_CONFIG_ISSUER_PUBKEY_ENV),
            "the refusal must name the pin: {err}"
        );

        // And a DIFFERENT issuer is refused even though its signature is
        // perfectly valid — the substitution the pin exists to catch.
        let other = veil_crypto::generate_keypair(crate::SignatureAlgorithm::Ed25519);
        assert!(load_config_with_policy(&path, Some(&other.public_key), false).is_err());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&root);
    }
}
