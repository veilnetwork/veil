//! Operator-facing inspection + control API on `NodeRuntime`.
//!
//! Two categories of methods, intentionally co-located because they all
//! map 1:1 to `AdminCommand` variants and to `node`-CLI subcommands:
//!
//! **Read accessors** (`summary`, `listens`, `sessions`, `peers`,
//! `loss_tracker_snapshot`, `bandwidth_stats`, `list_bans`,
//! `sovereign_identity`, `config_path`) — snapshot copies of mutable
//! state for display.
//! **Operator mutators** (`broadcast_epidemic`, `ban_node`,
//! `unban_node`, `kill_session`) — admin actions invoked from
//! `veil node …` subcommands.
//!
//! Extracted from `runtime/mod.rs` during refactor.

use std::sync::Arc;
use veil_util::lock;

use crate::types::{ListenConfigEntry, NodeId, NodeSummary, PeerConfigEntry, SessionInfo};

use super::NodeRuntime;
use super::persistence::persist_bans;

impl NodeRuntime {
    pub fn summary(&self) -> NodeSummary {
        let sessions_active = lock!(self.live_sessions).len();
        self.lock_state().summary(sessions_active)
    }

    pub fn config_path(&self) -> &std::path::Path {
        &self.config_path
    }

    /// Loaded sovereign identity, if this node was
    /// provisioned via `veil-cli identity create` or restored
    /// from a BIP-39 phrase. `None` for legacy (node_id-keyed)
    /// nodes. Returned as an `Arc` clone so callers can hold it
    /// without taking a borrow on the runtime.
    pub fn sovereign_identity(&self) -> Option<Arc<veil_identity::sovereign::SovereignIdentity>> {
        self.identity.sovereign_identity.get()
    }

    pub fn listens(&self) -> Vec<ListenConfigEntry> {
        self.lock_state().listens.values().cloned().collect()
    }

    pub fn sessions(&self) -> Vec<SessionInfo> {
        lock!(self.live_sessions).values().cloned().collect()
    }

    /// snapshot of the per-peer in-line loss tracker for admin
    /// surfaces (`node sessions`). Returns `(peer_id, last_loss_rate_0..1,
    /// last_samples)` for every peer with a fully-evaluated window.
    pub fn loss_tracker_snapshot(&self) -> Vec<([u8; 32], f32, u32)> {
        self.dispatcher.loss_tracker.snapshot()
    }

    pub fn peers(&self) -> Vec<PeerConfigEntry> {
        self.lock_state().peers.values().cloned().collect()
    }

    // cleanup: `broadcast_epidemic` runtime method removed.
    // module docstring listed this as operator-mutator admin
    // action, but no `AdminCommand` variant, CLI subcommand, or IPC handler
    // ever surfaced it. Inbound `EpidemicBroadcast` frames go directly via
    // `dispatcher/control.rs:520 → app_registry.broadcast_epidemic` bypassing
    // this method entirely. Re-introduce from git history if
    // `AdminCommand::BroadcastEpidemic` actually ships.

    /// Permanently ban `node_id` from connecting (runtime only, not persisted).
    /// Permanently ban `node_id` and tear down any currently-active session
    /// to it. Without the tear-down step, bans only blocked NEW handshakes
    /// while existing sessions (both inbound and outbound) kept running —
    /// so `peers ban` felt silent, and the banned peer kept exchanging
    /// frames until the TCP connection died on its own.
    pub fn ban_node(&self, node_id: NodeId) {
        // Tear-down first so (manual, persistent) ban entry installed
        // below isn't overwritten by `kill_session`'s 30s auto-ban entry.
        // Both operations touch `BanList::entries` by key — last writer wins.
        self.tear_down_session(node_id);
        self.ban_list
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ban_manual(*node_id.as_bytes(), "admin ban");
        if let Some(m) = &self.metrics {
            m.inc_ban_actions();
        }
        persist_bans(&self.ban_list, &self.config_path);
    }

    /// Force-close every active session to `node_id` (both inbound and
    /// outbound) without installing a ban. Shared by `kill_session`
    /// (adds 30s auto-ban) and `ban_node` (installs persistent ban
    ///
    fn tear_down_session(&self, node_id: NodeId) {
        let id_bytes = *node_id.as_bytes();
        self.session_tx_registry
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .unregister(&id_bytes);
        // Admin/inspection teardown path — not a referral session.
        self.dispatcher.on_session_closed(node_id, false);
        lock!(self.live_sessions).retain(|_, s| s.node_id.as_ref() != Some(&node_id));
    }

    /// Lift a runtime ban previously applied by [`ban_node`](Self::ban_node).
    pub fn unban_node(&self, node_id: NodeId) {
        self.ban_list
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unban(node_id.as_bytes());
        persist_bans(&self.ban_list, &self.config_path);
    }

    /// Toggle the mobile background-mode flag.
    /// Atomic — flips the runtime's `AtomicBool` AND the
    /// process-global signal that session runners read on every
    /// keepalive recomputation tick (composes multiplicatively
    /// with battery scaling). Backgrounded + low-battery →
    /// both factors apply.
    pub fn set_mobile_background_mode(&self, enabled: bool) {
        self.mobile
            .mobile_background_mode
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        veil_session::runner::set_mobile_background_mode(enabled);
    }

    /// Read the current mobile background-mode flag.
    /// Cheap atomic load — used by inspection / admin diag.
    pub fn mobile_background_mode(&self) -> bool {
        self.mobile
            .mobile_background_mode
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Snapshot of mobile-mode runtime state.
    /// Reads battery from /sys (Linux) / sentinel 100 elsewhere,
    /// reads runtime AtomicBool, reads config knobs from already-
    /// loaded MobileConfig. No network I/O, no admin roundtrip
    /// cost beyond IPC ping.
    pub fn mobile_status(&self) -> crate::admin::AdminMobileStatus {
        // Reload config off disk (mirrors UpdateStatus / BootstrapStatus
        // semantics — operator who edited [mobile] section gets fresh
        // snapshot without admin reload).
        let config_snapshot = veil_cfg::load_config(&self.config_path)
            .unwrap_or_else(|_| veil_cfg::Config::default());
        let mobile_cfg = &config_snapshot.mobile;

        let background_mode = self.mobile_background_mode();
        let battery_level_pct = crate::runtime::local_battery_level();

        crate::admin::AdminMobileStatus {
            background_mode,
            background_keepalive_multiplier: mobile_cfg.background_keepalive_multiplier,
            background_keepalive_factor: mobile_cfg.background_keepalive_factor(background_mode),
            battery_level_pct,
            low_battery_threshold_pct: mobile_cfg.low_battery_threshold_pct,
            low_battery_multiplier: mobile_cfg.low_battery_multiplier,
            battery_route_probe_factor: mobile_cfg.battery_multiplier(battery_level_pct),
        }
    }

    /// Snapshot of the update mechanism state. Reads
    /// already-loaded config + the on-disk InstalledVersionStore;
    /// no network I/O. Disk read is best-effort — a missing /
    /// corrupt state file surfaces `installed_release_unix = None`
    /// (treated as "fresh install" by check semantics). Operators
    /// debugging "why is my installed version empty" can run
    /// `veil-cli update check` to see the real fetch + verify
    /// errors with full diagnostics.
    pub fn update_status(&self) -> crate::admin::AdminUpdateStatus {
        // Reload config off disk so the snapshot reflects edits
        // made since startup (matches BootstrapStatus semantics —
        // operator who edited [update] section gets fresh view
        // without admin reload).
        let config_snapshot = veil_cfg::load_config(&self.config_path).unwrap_or_else(|_| {
            // Fall back to a default config so the field-by-field
            // reads below produce sensible "feature off" output
            // when the config file is missing / unreadable.
            // Doesn't propagate the read error — admin status is
            // a "best-effort snapshot" surface; operators see
            // real config errors via `veil-cli config show`.
            veil_cfg::Config::default()
        });
        let update_cfg = &config_snapshot.update;

        let installed_release_unix = update_cfg.installed_version_path.as_ref().and_then(|path| {
            let store = veil_update::installed_version::InstalledVersionStore::new(path.clone());
            store.read_release_unix().ok().flatten()
        });

        crate::admin::AdminUpdateStatus {
            check_configured: update_cfg.is_check_enabled(),
            apply_configured: update_cfg.is_apply_enabled(),
            manifest_url_count: update_cfg.manifest_urls.len(),
            check_interval_secs: update_cfg.check_interval_secs,
            installed_release_unix,
            mobile_background_mode: self.mobile_background_mode(),
        }
    }

    /// Return bandwidth utilization stats.
    /// Returns 9-tuple: `(inbound_kbps, outbound_kbps,
    /// in_total_bytes, in_dropped_bytes, out_total_bytes,
    /// out_dropped_bytes, per_peer_byte_cap, per_peer_allowed,
    /// per_peer_dropped)`. Per-peer fields surface as `-1` /
    /// `0` / `0` when per-peer byte-rate enforcement not enabled
    /// (default for non-mobile deployments).
    pub fn bandwidth_stats(&self) -> (i64, i64, u64, u64, u64, u64, i64, u64, u64) {
        let in_g = lock!(self.dispatcher.abuse.inbound_bandwidth);
        let out_g = lock!(self.dispatcher.abuse.outbound_bandwidth);
        let per_peer = lock!(self.rate_limiter);
        // Reload config off disk so the cap surfaces operator's
        // current intent (matches BootstrapStatus / UpdateStatus
        // / MobileStatus semantics — operator who edited
        // [abuse].per_peer_bytes_per_sec gets fresh view without
        // admin reload).
        let cap = veil_cfg::load_config(&self.config_path)
            .ok()
            .and_then(|c| c.abuse.per_peer_bytes_per_sec)
            .map(|v| v as i64)
            .unwrap_or(-1);
        (
            if in_g.is_unlimited() {
                -1
            } else {
                in_g.limit_kbps() as i64
            },
            if out_g.is_unlimited() {
                -1
            } else {
                out_g.limit_kbps() as i64
            },
            in_g.total_bytes,
            in_g.dropped_bytes,
            out_g.total_bytes,
            out_g.dropped_bytes,
            cap,
            per_peer.bytes_allowed_total(),
            per_peer.bytes_dropped_total(),
        )
    }

    /// Kill a session: tear down active sessions to the peer and apply a
    /// short auto-ban to prevent immediate reconnection. Use
    /// [`ban_node`](Self::ban_node) for a permanent, persistent ban.
    pub fn kill_session(&self, node_id: NodeId) {
        self.tear_down_session(node_id);
        // Short auto-ban (30s) to prevent outbound connector from
        // immediately reconnecting. Manual `peers ban` gives permanent ban.
        self.ban_list.lock().unwrap_or_else(|p| p.into_inner()).ban(
            *node_id.as_bytes(),
            "session killed",
            Some(std::time::Duration::from_secs(30)),
        );
    }

    /// List all currently active bans.
    ///
    /// Returns `(node_id_hex, reason, manual, banned_at_unix)` tuples;
    /// the last field is `None` for bans restored from pre-468.4
    /// `bans.json` that didn't carry a timestamp.
    pub fn list_bans(&self) -> Vec<(String, String, bool, Option<u64>)> {
        let bl = self.ban_list.lock().unwrap_or_else(|p| p.into_inner());
        bl.active_bans()
            .iter()
            .map(|e| {
                let banned_at_unix = e
                    .banned_at
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                (
                    veil_util::hex_str(&e.peer_id),
                    e.reason.clone(),
                    e.manual,
                    banned_at_unix,
                )
            })
            .collect()
    }
}
