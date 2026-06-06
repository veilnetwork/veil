//! IPC → runtime adapter for `GetMobileStatus`.
//!
//! Implements [`veil_ipc::MobileStatusProvider`] over the runtime's
//! global mobile/battery atomics + the on-disk `[mobile]` config.
//! Constructed in `spawn_ipc_server`.

use std::path::PathBuf;

use veil_ipc::MobileStatusProvider;
use veil_proto::{
    MOBILE_BATTERY_AC_OR_UNKNOWN, MOBILE_LOW_BATTERY_THRESHOLD_DISABLED, MobileStatusPayload,
};

/// Snapshots the daemon's current mobile/battery state for IPC clients.
pub struct RuntimeMobileStatus {
    /// Path to the on-disk config; reloaded on every snapshot so the
    /// reply reflects edits made since startup (mirrors UpdateStatus /
    /// BootstrapStatus semantics — operator who tweaked `[mobile]`
    /// gets fresh view без admin reload).
    config_path: PathBuf,
}

impl RuntimeMobileStatus {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }
}

impl MobileStatusProvider for RuntimeMobileStatus {
    fn mobile_status(&self) -> MobileStatusPayload {
        // Reload config off disk so operator-side edits are visible.
        let config = veil_cfg::load_config(&self.config_path)
            .unwrap_or_else(|_| veil_cfg::Config::default());
        let mobile_cfg = &config.mobile;

        let tier = veil_session::runner::current_mobile_background_tier();
        let multiplier = veil_session::runner::current_mobile_background_keepalive_multiplier();
        let factor = veil_session::runner::current_mobile_background_keepalive_factor();

        // Battery + low-battery throttle factor — mirror
        // `MobileConfig::battery_multiplier` semantics. Sentinels:
        // battery=100 means AC / unknown (never throttled); threshold=255
        // means feature disabled.
        let battery_level_pct = crate::runtime::local_battery_level();
        let low_battery_threshold_pct = mobile_cfg
            .low_battery_threshold_pct
            .unwrap_or(MOBILE_LOW_BATTERY_THRESHOLD_DISABLED);
        let battery_route_probe_factor = mobile_cfg.battery_multiplier(battery_level_pct);

        // The 100-sentinel is set by `local_battery_level` itself when
        // the platform doesn't expose battery info or the file read
        // fails — we surface it as `MOBILE_BATTERY_AC_OR_UNKNOWN` so
        // apps can distinguish "literal 100% battery" from "unknown".
        // The two ARE the same numeric value at the wire layer — apps
        // that want to disambiguate must rely on their own platform
        // signals (e.g. Flutter's `battery_plus` package). Documented
        // in the proto module.
        let _ = MOBILE_BATTERY_AC_OR_UNKNOWN; // referenced for doc-rustdoc

        MobileStatusPayload {
            background_tier: tier,
            background_keepalive_multiplier: multiplier,
            background_keepalive_factor: factor,
            battery_level_pct,
            low_battery_threshold_pct,
            low_battery_multiplier: mobile_cfg.low_battery_multiplier,
            battery_route_probe_factor,
        }
    }
}
