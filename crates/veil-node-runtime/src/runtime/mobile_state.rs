//! decomposition PR3: mobile / battery-tier
//! state extracted into а dedicated [`Arc<MobileState>`].
//!
//! ## Why а dedicated struct
//!
//! Pre-PR3, `NodeRuntime` held five mobile-domain fields directly:
//! one live atomic flag (`mobile_background_mode`) and four
//! config-derived snapshots (battery scaling thresholds + scales).
//! These snapshots were ALSO mirrored on `NodeServices` and
//! `SessionRuntimeContext` — 15 field declarations across the three
//! structs, all kept manually in sync at builder time.
//!
//! Wrapping them in `Arc<MobileState>` collapses the three contexts'
//! field set к а single Arc each, и centralises the "snapshot-at-clone"
//! semantics that PR1 (`AnonymityState`) и PR2 (`MailboxState`)
//! established.
//!
//! ## What's в this bundle
//!
//! * `mobile_background_mode` — live AtomicBool toggled by mobile
//!   foreground/background hooks. Read on every keepalive tick.
//! * `battery_keepalive_scale_low` / `_medium` — multipliers applied
//!   к base keepalive when the device's battery level crosses
//!   thresholds. Snapshots от `cfg.session`; updated on `reload`
//!   via а fresh `Arc<MobileState>` swap (matches PR1 reload semantics).
//! * `battery_threshold_low` / `_medium` — tier-boundary battery
//!   percentages (e.g. low ≤ 20%, medium ≤ 50%). Same snapshot
//!   semantics as the scales.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Mobile / battery-tier state owned by [`crate::node::NodeRuntime`].
pub struct MobileState {
    /// mobile background-mode flag, toggled by the GUI
    /// wrapper / mobile app via `AdminCommand::SetMobileBackgroundMode`
    /// от onPause / onResume hooks. When `true`, per-session keepalive
    /// intervals are multiplied by `cfg.mobile.background_keepalive_multiplier`
    /// (clamped at `MAX_BACKGROUND_KEEPALIVE_MULTIPLIER`) so sessions
    /// survive OS-level app suspension. Atomic — flipped без holding
    /// any locks; session runners read on every keepalive recomputation
    /// tick. Kept across reload (the operator-controlled multiplier
    /// snapshot lives elsewhere).
    pub mobile_background_mode: Arc<AtomicBool>,

    /// battery keepalive scale при low-battery tier.
    /// Snapshot from `cfg.session.battery_keepalive_scale_low` at
    /// startup / reload. Read by session runners when the local
    /// battery level falls below `battery_threshold_low`.
    pub battery_keepalive_scale_low: f32,

    /// battery keepalive scale при medium-battery tier.
    pub battery_keepalive_scale_medium: f32,

    /// battery level threshold (percentage) defining the
    /// "low" tier — readings at-or-below this percentage trigger
    /// the `_scale_low` multiplier.
    pub battery_threshold_low: u8,

    /// battery level threshold (percentage) defining the
    /// "medium" tier.
    pub battery_threshold_medium: u8,
}

impl MobileState {
    pub fn new(
        mobile_background_mode: Arc<AtomicBool>,
        battery_keepalive_scale_low: f32,
        battery_keepalive_scale_medium: f32,
        battery_threshold_low: u8,
        battery_threshold_medium: u8,
    ) -> Self {
        Self {
            mobile_background_mode,
            battery_keepalive_scale_low,
            battery_keepalive_scale_medium,
            battery_threshold_low,
            battery_threshold_medium,
        }
    }
}
