//! End-to-end update-check orchestrator.
//!
//! Wraps the building blocks shipped in slices 1-6:
//! * [`UpdateConfig`] — operator's manifest URLs + expected issuer
//!   public key + installed-version state file path.
//! * [`InstalledVersionStore`] — reads the
//!   `installed_release_unix` of the currently-installed binary.
//! * [`check_for_update_via_https`] — fetches + verifies the
//!   operator's signed manifest over real TLS.
//!
//! Future CLI command (`veil-cli update --check`) and runtime
//! background task (periodic poll → log "update available") both
//! compose against this single entrypoint — no caller has to
//! re-derive the wiring.
//!
//! # Why a single struct (not two free functions)
//!
//! Two callers need this orchestration: (a) the CLI command and
//! (b) the runtime background task. Sharing a single struct
//! makes sure both follow the same flow: load installed version
//! consistently, surface UpdateNotConfigured uniformly, treat
//! missing state file as "fresh install" (not error). Without
//! the wrapper, those policy choices would drift between callers
//! and produce subtly different observable behaviour.

use veil_transport::TransportContext;
use veil_types::UpdateConfig;

use super::fetch::{FetchError, UpdateAvailability, check_for_update_via_https};
use super::installed_version::{InstalledVersionError, InstalledVersionStore};

/// Absolute lower bound for a believable wall clock, used only in the
/// "no installed version recorded" (check-only) mode where there is no
/// on-device release timestamp to floor against. 2024-01-01 UTC. When
/// an install IS recorded, the running binary's own `release_unix` is a
/// tighter, self-updating floor (a binary cannot run before it shipped),
/// so this constant is deliberately conservative rather than tracking
/// "now" — its only job is to catch an epoch-zero / CMOS-reset clock.
const MIN_PLAUSIBLE_WALL_CLOCK_UNIX: u64 = 1_704_067_200;

#[derive(Debug, thiserror::Error)]
pub enum CheckerError {
    /// `UpdateConfig` is missing required fields — see
    /// [`UpdateConfig::is_check_enabled`]. Returned WITHOUT touching
    /// the network so a node that didn't opt in doesn't accidentally
    /// reach out to the operator's CDN.
    #[error("update mechanism not configured (manifest_urls + expected_issuer_pk required)")]
    NotConfigured,
    /// Failed to read the installed-version state file. Different
    /// from "file does not exist" (which is a fresh install and
    /// treated as `installed_release_unix = 0`).
    #[error("read installed version: {0}")]
    InstalledVersion(InstalledVersionError),
    /// Manifest fetch / verify / failover failed.
    #[error("fetch: {0}")]
    Fetch(FetchError),
}

impl From<InstalledVersionError> for CheckerError {
    fn from(e: InstalledVersionError) -> Self {
        Self::InstalledVersion(e)
    }
}
impl From<FetchError> for CheckerError {
    fn from(e: FetchError) -> Self {
        Self::Fetch(e)
    }
}

/// End-to-end update-check orchestrator. Build once per operation
/// (CLI invocation, periodic poll); cheap to construct.
pub struct UpdateChecker {
    config: UpdateConfig,
    transport_ctx: TransportContext,
}

impl UpdateChecker {
    pub fn new(config: UpdateConfig, transport_ctx: TransportContext) -> Self {
        Self {
            config,
            transport_ctx,
        }
    }

    /// Run a check. Steps:
    /// 1. Verify the operator opted in.
    /// 2. Load `installed_release_unix` (None == fresh install
    ///    == treat as `0`).
    /// 3. Fetch + verify manifest from any of `manifest_urls`.
    /// 4. Compare release_unix → UpdateAvailability.
    pub async fn check(&self) -> Result<UpdateAvailability, CheckerError> {
        if !self.config.is_check_enabled() {
            return Err(CheckerError::NotConfigured);
        }
        // P1: defended above by is_check_enabled, but a future
        // misuse (caller bypasses validation with a half-configured
        // UpdateConfig) must surface as `NotConfigured` rather than
        // a release-time `panic = abort`.
        let issuer_pk = self
            .config
            .expected_issuer_pk
            .as_deref()
            .ok_or(CheckerError::NotConfigured)?;
        let installed_release_unix = self.read_installed_release_unix()?;
        // Pass current wall-clock time to the verifier so it can enforce
        // the manifest's future-skew + staleness gates. If the system
        // clock is implausibly early it is unusable as a freshness
        // reference: fall back to `None` (both gates disabled) rather
        // than blocking updates on a CMOS-reset device.
        //
        // Plausibility floor = the running binary's own `release_unix`
        // (you cannot be executing a binary before it was published — a
        // self-updating, non-stale bound) OR an absolute constant for
        // the check-only mode where no install timestamp is recorded.
        // This replaces a frozen 2023 magic number that grew staler
        // every year. Note we do NOT substitute the floor *for* `now`:
        // doing so would reject legitimately newer manifests via the
        // very future-skew gate we are trying to preserve. Disabling is
        // the least-bad option for a bogus clock — but we WARN so the
        // weakened-verification state is observable instead of silent.
        let now_raw = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        let plausibility_floor = installed_release_unix.max(MIN_PLAUSIBLE_WALL_CLOCK_UNIX);
        let now_unix_secs = now_raw.filter(|t| *t >= plausibility_floor);
        if now_unix_secs.is_none() {
            log::warn!(
                "update check: system clock ({now_raw:?}) is below the plausibility \
                 floor ({plausibility_floor}); manifest freshness gates (future-skew \
                 + staleness) are DISABLED for this check. Anti-downgrade still \
                 applies. Correct the device clock to restore full verification."
            );
        }
        let availability = check_for_update_via_https(
            &self.config.manifest_urls,
            self.transport_ctx.clone(),
            issuer_pk,
            installed_release_unix,
            now_unix_secs,
        )
        .await?;
        Ok(availability)
    }

    /// Read installed release_unix. None on disk → 0 (fresh
    /// install — any signed manifest is "newer").
    fn read_installed_release_unix(&self) -> Result<u64, CheckerError> {
        let Some(ref path) = self.config.installed_version_path else {
            // No state file configured. This is the supported "check-
            // only" mode: operator runs `update --check` from a
            // package-manager-installed binary; the manifest is just
            // for "hey, version X published" notification, no apply
            // path. Treat as `0` so any signed manifest reports
            // Available.
            return Ok(0);
        };
        let store = InstalledVersionStore::new(path.clone());
        Ok(store.read_release_unix()?.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn unique_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("veil-checker-{label}-{pid}-{nanos}.json"))
    }

    fn debug_ctx() -> TransportContext {
        TransportContext::for_debug().expect("debug ctx")
    }

    #[tokio::test]
    async fn epic484_3_checker_not_configured_when_update_config_default() {
        // Default UpdateConfig (no manifest_urls, no issuer pk) →
        // check returns NotConfigured WITHOUT touching the network.
        let checker = UpdateChecker::new(UpdateConfig::default(), debug_ctx());
        let err = checker.check().await.unwrap_err();
        assert!(matches!(err, CheckerError::NotConfigured));
    }

    #[tokio::test]
    async fn epic484_3_checker_not_configured_when_only_urls_set() {
        // Half-configured: manifest_urls without expected_issuer_pk.
        // This SHOULD also be caught by config validation
        // but the orchestrator must defend regardless — defence in
        // depth against a bypass of validation.
        let config = UpdateConfig {
            manifest_urls: vec!["https://m.example/m".to_owned()],
            expected_issuer_pk: None,
            installed_version_path: None,
            check_interval_secs: None,
            install_path: None,
        };
        let checker = UpdateChecker::new(config, debug_ctx());
        let err = checker.check().await.unwrap_err();
        assert!(
            matches!(err, CheckerError::NotConfigured),
            "half-config (urls only) must NOT reach the network"
        );
    }

    #[tokio::test]
    async fn epic484_3_checker_not_configured_when_only_issuer_set() {
        let config = UpdateConfig {
            manifest_urls: Vec::new(),
            expected_issuer_pk: Some("0".repeat(64)),
            installed_version_path: None,
            check_interval_secs: None,
            install_path: None,
        };
        let checker = UpdateChecker::new(config, debug_ctx());
        let err = checker.check().await.unwrap_err();
        assert!(
            matches!(err, CheckerError::NotConfigured),
            "half-config (issuer only) must NOT reach the network"
        );
    }

    #[tokio::test]
    async fn epic484_3_checker_treats_missing_state_file_as_fresh_install() {
        // Configured + state path points at a file that doesn't
        // exist. read_installed_release_unix must return 0 (not
        // error) so the check can proceed (any signed manifest
        // reports Available against installed=0).
        let config = UpdateConfig {
            manifest_urls: vec!["https://m.example/m".to_owned()],
            expected_issuer_pk: Some("0".repeat(64)),
            installed_version_path: Some(unique_path("missing-state")),
            check_interval_secs: None,
            install_path: None,
        };
        let checker = UpdateChecker::new(config, debug_ctx());
        // The fetch will fail because https://m.example doesn't resolve
        // BUT the InstalledVersionStore read step must NOT short-circuit
        // with InstalledVersion error. We assert the error type is
        // Fetch (network), not InstalledVersion (file).
        let err = checker.check().await.unwrap_err();
        assert!(
            matches!(err, CheckerError::Fetch(_)),
            "missing state file must be treated as fresh install, not surfaced as InstalledVersion error: {err:?}"
        );
    }

    #[tokio::test]
    async fn epic484_3_checker_uses_zero_when_no_state_path_configured() {
        // installed_version_path = None is the supported "check-only"
        // mode (package-manager-installed binary, no apply path).
        // Must not error out — instead use installed=0 so the check
        // completes.
        let config = UpdateConfig {
            manifest_urls: vec!["https://m.example/m".to_owned()],
            expected_issuer_pk: Some("0".repeat(64)),
            installed_version_path: None,
            check_interval_secs: None,
            install_path: None,
        };
        let checker = UpdateChecker::new(config, debug_ctx());
        // As above, the fetch will fail (network), but error type
        // tells us we got past the installed-version step.
        let err = checker.check().await.unwrap_err();
        assert!(
            matches!(err, CheckerError::Fetch(_)),
            "no state path must mean installed=0, not error: {err:?}"
        );
    }

    #[tokio::test]
    async fn epic484_3_checker_surfaces_corrupt_state_file_loudly() {
        // Inverse of "missing → fresh install": a CORRUPT state file
        // (existed but unreadable JSON) MUST surface as
        // InstalledVersion error. Otherwise we'd silently treat it
        // as fresh install and report any manifest as Available
        // which would misclassify a real installed version as
        // "needs update" and could trigger a downgrade.
        let path = unique_path("corrupt-state");
        std::fs::write(&path, b"this is not valid json").unwrap();
        let config = UpdateConfig {
            manifest_urls: vec!["https://m.example/m".to_owned()],
            expected_issuer_pk: Some("0".repeat(64)),
            installed_version_path: Some(path.clone()),
            check_interval_secs: None,
            install_path: None,
        };
        let checker = UpdateChecker::new(config, debug_ctx());
        let err = checker.check().await.unwrap_err();
        assert!(
            matches!(err, CheckerError::InstalledVersion(_)),
            "corrupt state file MUST surface loudly, not silently fall back to installed=0: {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
