//! Owner-side freshness helpers.
//!
//! `IdentityDocument` carries a short `valid_until_unix` that
//! verifiers reject after expiry. The owner must periodically
//! re-issue the document with a fresh window. In the
//! separate `master_freshness_sig` was removed — there is no longer
//! a "refresh just the cert" path; an owner that wants to extend
//! `valid_until_unix` must produce a new signed document via
//! `cfg::sovereign_flow::rotate_identity` (or a future dedicated
//! re-issue helper).
//!
//! This module now exposes only the **status / scheduling** half of
//! the lifecycle:
//!
//! [`needs_refresh`] — predicate the daemon polls periodically:
//! "is `valid_until_unix` close enough to expiry that we should
//! re-issue now?"
//! [`severity`] — graded warning level for monitoring UIs.
//! [`FreshnessConfig`] — operator-tunable thresholds.

use std::time::Duration;

use veil_proto::identity_document::{IdentityDocument, MAX_FRESHNESS_WINDOW_SECS};

// ── Config ───────────────────────────────────────────────────────────────────

/// Operator-tunable thresholds for the freshness lifecycle.
#[derive(Debug, Clone, Copy)]
pub struct FreshnessConfig {
    /// How far into the future a refresh sets `valid_until_unix`.
    /// Capped by [`MAX_FRESHNESS_WINDOW_SECS`] (30 days).
    pub window: Duration,
    /// Once `now + auto_refresh_at_remaining ≥ valid_until_unix`
    /// [`needs_refresh`] returns `true`. Default: 5 days before
    /// expiry (matches the spec's 30-day window minus the
    /// recommended 25-day cadence).
    pub auto_refresh_at_remaining: Duration,
    /// Once `now + warn_at_remaining ≥ valid_until_unix`
    /// [`severity`] graduates from `Healthy` to `Warning`.
    /// Default: 10 days.
    pub warn_at_remaining: Duration,
}

impl FreshnessConfig {
    pub const DEFAULT_WINDOW_DAYS: u64 = 30;
    pub const DEFAULT_REFRESH_AT_REMAINING_DAYS: u64 = 5;
    pub const DEFAULT_WARN_AT_REMAINING_DAYS: u64 = 10;

    /// Spec-default: 30-day window, refresh at 5d-remaining, warn at
    /// 10d-remaining.
    pub fn defaults() -> Self {
        Self {
            window: Duration::from_secs(Self::DEFAULT_WINDOW_DAYS * 86_400),
            auto_refresh_at_remaining: Duration::from_secs(
                Self::DEFAULT_REFRESH_AT_REMAINING_DAYS * 86_400,
            ),
            warn_at_remaining: Duration::from_secs(Self::DEFAULT_WARN_AT_REMAINING_DAYS * 86_400),
        }
    }

    /// Validate that the window is within protocol bounds and the
    /// thresholds are coherent (warn ≥ refresh). Returns
    /// `Err(reason)` if the configuration is unusable.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.window.as_secs() == 0 || self.window.as_secs() > MAX_FRESHNESS_WINDOW_SECS {
            return Err("window must be > 0 and ≤ MAX_FRESHNESS_WINDOW_SECS");
        }
        if self.warn_at_remaining < self.auto_refresh_at_remaining {
            return Err("warn_at_remaining must be ≥ auto_refresh_at_remaining");
        }
        if self.auto_refresh_at_remaining >= self.window {
            return Err("auto_refresh_at_remaining must be < window");
        }
        Ok(())
    }
}

// ── Status ───────────────────────────────────────────────────────────────────

/// Output [`severity`] — graded warning level for monitoring UIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessSeverity {
    /// Plenty of headroom — no action required.
    Healthy,
    /// Approaching expiry; UI should surface a non-blocking warning.
    Warning,
    /// Refresh threshold reached; daemon should kick off the
    /// refresh now (or prompt the user if interactive).
    NeedsRefresh,
    /// Already expired — verifiers will reject. Identity is
    /// effectively offline until refreshed.
    Expired,
}

/// Computed status of a document's freshness window relative to
/// `now`.
pub fn severity(
    doc: &IdentityDocument,
    now_unix_secs: u64,
    cfg: &FreshnessConfig,
) -> FreshnessSeverity {
    if now_unix_secs >= doc.valid_until_unix {
        return FreshnessSeverity::Expired;
    }
    let remaining_secs = doc.valid_until_unix - now_unix_secs;
    if remaining_secs <= cfg.auto_refresh_at_remaining.as_secs() {
        FreshnessSeverity::NeedsRefresh
    } else if remaining_secs <= cfg.warn_at_remaining.as_secs() {
        FreshnessSeverity::Warning
    } else {
        FreshnessSeverity::Healthy
    }
}

/// Convenience: `severity == NeedsRefresh || Expired`.
pub fn needs_refresh(doc: &IdentityDocument, now_unix_secs: u64, cfg: &FreshnessConfig) -> bool {
    matches!(
        severity(doc, now_unix_secs, cfg),
        FreshnessSeverity::NeedsRefresh | FreshnessSeverity::Expired
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use veil_crypto::identity::{compute_node_id, derive_master_sk_ed25519};
    use veil_proto::identity_document::{ALGO_ED25519, IdentityKey};

    fn build_doc_with_master(valid_until_unix: u64) -> IdentityDocument {
        let seed = [0x42u8; 32];
        let sk_bytes = derive_master_sk_ed25519(&seed);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();
        let node_id = compute_node_id(pk.as_bytes());

        IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: pk.as_bytes().to_vec(),
            issued_at_unix: 1_700_000_000,
            valid_until_unix,
            sig_key_idx: 0,
            identity_keys: vec![IdentityKey {
                algo: ALGO_ED25519,
                pubkey: vec![0xAA; 32],
                device_id: compute_node_id(&[0xAA; 32]),
                valid_from_unix: 1_700_000_000,
                valid_until_unix: 1_700_000_000 + 7 * 86_400,
                master_sig: vec![0xCC; 64],
            }],
            document_sig: vec![0xFF; 64],
        }
    }

    fn cfg_default() -> FreshnessConfig {
        FreshnessConfig::defaults()
    }

    #[test]
    fn healthy_when_far_from_expiry() {
        let now: u64 = 1_700_000_000;
        let doc = build_doc_with_master(now + 30 * 86_400); // exactly window
        assert_eq!(
            severity(&doc, now, &cfg_default()),
            FreshnessSeverity::Healthy
        );
        assert!(!needs_refresh(&doc, now, &cfg_default()));
    }

    #[test]
    fn warning_inside_warn_window() {
        let now: u64 = 1_700_000_000;
        // 8 days remaining: > 5d (refresh) but ≤ 10d (warn).
        let doc = build_doc_with_master(now + 8 * 86_400);
        assert_eq!(
            severity(&doc, now, &cfg_default()),
            FreshnessSeverity::Warning
        );
        assert!(!needs_refresh(&doc, now, &cfg_default()));
    }

    #[test]
    fn needs_refresh_inside_refresh_window() {
        let now: u64 = 1_700_000_000;
        let doc = build_doc_with_master(now + 4 * 86_400); // 4 days
        assert_eq!(
            severity(&doc, now, &cfg_default()),
            FreshnessSeverity::NeedsRefresh
        );
        assert!(needs_refresh(&doc, now, &cfg_default()));
    }

    #[test]
    fn expired_when_past_valid_until() {
        let now: u64 = 1_700_000_000;
        let doc = build_doc_with_master(now - 1);
        assert_eq!(
            severity(&doc, now, &cfg_default()),
            FreshnessSeverity::Expired
        );
        assert!(needs_refresh(&doc, now, &cfg_default()));
    }

    #[test]
    fn config_defaults_validate() {
        FreshnessConfig::defaults().validate().unwrap();
    }

    #[test]
    fn config_validate_rejects_window_above_max() {
        let cfg = FreshnessConfig {
            window: Duration::from_secs(MAX_FRESHNESS_WINDOW_SECS + 1),
            ..FreshnessConfig::defaults()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_warn_below_refresh() {
        let cfg = FreshnessConfig {
            warn_at_remaining: Duration::from_secs(86_400),
            auto_refresh_at_remaining: Duration::from_secs(7 * 86_400),
            ..FreshnessConfig::defaults()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_refresh_above_window() {
        let cfg = FreshnessConfig {
            window: Duration::from_secs(86_400),
            auto_refresh_at_remaining: Duration::from_secs(2 * 86_400),
            warn_at_remaining: Duration::from_secs(2 * 86_400),
        };
        assert!(cfg.validate().is_err());
    }
}
