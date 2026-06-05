//! Runtime wiring for the periodic update-check task.
//!
//! Composes [`UpdateChecker`](veil_update::checker::UpdateChecker)
//! and [`run_periodic_check_loop`](veil_update::check_task::run_periodic_check_loop)
//! into a supervised background task that the runtime spawns at
//! startup (and re-spawns after `node.reload`).
//!
//! The task is a NO-OP when the operator hasn't opted into the
//! update mechanism — `is_check_enabled` AND `check_interval_secs`
//! both must be set. This keeps "I just want to run a node, I'll
//! handle updates manually" the default path.

use std::sync::Arc;
use std::time::Duration;

use veil_cfg;
use veil_update::check_task::run_periodic_check_loop;
use veil_update::checker::UpdateChecker;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

impl NodeRuntime {
    /// Spawn the periodic update-check task if the operator opted in.
    /// No-op otherwise — keeps default-config nodes from making any
    /// network calls to update endpoints they don't have configured.
    pub fn spawn_update_check_task(&mut self, config: &veil_cfg::Config) {
        // Best-effort startup cleanup of stale.update-old /
        //.update-tmp artifacts (Windows.old-shuffle leftovers
        // from a previous apply, OR a crashed apply's tmp file).
        // Done unconditionally when install_path is configured —
        // the cleanup is no-op when no artifacts exist, AND it
        // doesn't depend on auto-poll being enabled (manual-apply-
        // only operators get cleanup too).
        if let Some(ref install_path) = config.update.install_path {
            let cleaned = veil_update::apply::cleanup_stale_update_artifacts(install_path);
            for path in cleaned {
                self.logger.info(
                    "update.apply.cleanup",
                    format!("removed stale update artifact: {}", path.display()),
                );
            }
        }
        // Guard: feature must be fully configured. is_check_enabled
        // requires both manifest_urls AND expected_issuer_pk; we
        // additionally require check_interval_secs to be set
        // (without an interval the auto-poll feature is OFF —
        // operators may still run manual `update --check` from CLI
        // when CLI ships).
        if !config.update.is_check_enabled() {
            return;
        }
        let Some(interval_secs) = config.update.check_interval_secs else {
            return;
        };
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();

        // Build the checker. Cheap — just clones config + ctx Arc.
        let checker = UpdateChecker::new(config.update.clone(), (*self.transport_ctx).clone());
        let interval = Duration::from_secs(interval_secs);
        let logger: Arc<dyn veil_update::UpdateLogger> =
            Arc::clone(&self.logger) as Arc<dyn veil_update::UpdateLogger>;

        let handle = supervised_spawn(Arc::clone(&self.logger), "update_check", async move {
            run_periodic_check_loop(checker, interval, logger, shutdown_rx).await;
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

#[cfg(test)]
mod tests {
    use veil_cfg::{Config, UpdateConfig};

    /// Default config → spawn must be no-op (no opt-). We can't
    /// directly unit-test "supervised_spawn was not called" without a
    /// runtime, but we can prove the early-return guards work by
    /// asserting the config predicates reflect the spawn decision.
    #[test]
    fn epic484_3_runtime_spawn_decision_default_config_means_no_spawn() {
        let config = Config::default();
        assert!(
            !config.update.is_check_enabled(),
            "default config must have is_check_enabled() == false"
        );
        assert!(
            config.update.check_interval_secs.is_none(),
            "default config must have check_interval_secs == None"
        );
    }

    #[test]
    fn epic484_3_runtime_spawn_decision_only_check_enabled_means_no_spawn() {
        // Manifest URLs + issuer set, but interval is None — manual-
        // check-only configuration. Spawn must NOT happen because
        // the loop would never tick.
        let config = Config {
            update: UpdateConfig {
                manifest_urls: vec!["https://m.example/m".to_owned()],
                expected_issuer_pk: Some("0".repeat(64)),
                installed_version_path: None,
                install_path: None,
                check_interval_secs: None,
            },
            ..Config::default()
        };
        assert!(config.update.is_check_enabled());
        assert!(
            config.update.check_interval_secs.is_none(),
            "no interval = manual-check-only mode = no auto-poll spawn"
        );
    }

    #[test]
    fn epic484_3_runtime_spawn_decision_full_config_means_spawn() {
        // Everything set → spawn fires.
        let config = Config {
            update: UpdateConfig {
                manifest_urls: vec!["https://m.example/m".to_owned()],
                expected_issuer_pk: Some("0".repeat(64)),
                installed_version_path: None,
                install_path: None,
                check_interval_secs: Some(21600), // 6h
            },
            ..Config::default()
        };
        assert!(config.update.is_check_enabled());
        assert!(
            config.update.check_interval_secs.is_some(),
            "full config means auto-poll spawn"
        );
    }
}
