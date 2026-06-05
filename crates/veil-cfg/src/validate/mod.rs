mod identity;
mod report;
mod structural;

use crate::Config;
use crate::identity_ops::{IdentityPowParams, IdentityUseCases};
use crate::identity_policy::PowPolicy;

pub use report::{ValidationIssue, ValidationReport};

/// Validate a parsed `Config` against the canonical PoW policy and return a
/// `ValidationReport` of any issues found (non-destructive — `config` is
/// read-only).
pub fn validate(config: &Config) -> ValidationReport {
    validate_with_policy(config, &PowPolicy::canonical())
}

/// Same as [`validate`] but with a caller-supplied `PowPolicy`, used by the
/// CLI's `--difficulty-override` flag and tests that need a lighter PoW.
pub fn validate_with_policy(config: &Config, pow: &PowPolicy) -> ValidationReport {
    build_report(config, pow, 0)
}

/// Validate and apply in-place fixes for fixable issues (e.g. missing defaults
/// canonicalising enum strings). Returns the post-fix report; use this in
/// init/migration paths where a dirty config should be repaired.
pub fn validate_and_fix(config: &mut Config) -> crate::Result<ValidationReport> {
    validate_and_fix_with_policy(config, &PowPolicy::canonical())
}

/// Policy-parameterised variant [`validate_and_fix`].
pub fn validate_and_fix_with_policy(
    config: &mut Config,
    pow: &PowPolicy,
) -> crate::Result<ValidationReport> {
    let fixed = apply_fixes_with_policy(config, pow)?;
    Ok(build_report(config, pow, fixed))
}

fn build_report(config: &Config, pow: &PowPolicy, fixed: usize) -> ValidationReport {
    ValidationReport {
        issues: collect_issues(config, pow),
        fixed,
    }
}

fn collect_issues(config: &Config, pow: &PowPolicy) -> Vec<ValidationIssue> {
    structural::collect_issues(config)
        .into_iter()
        .chain(identity::collect_issues(config, pow))
        .collect()
}

fn apply_fixes_with_policy(config: &mut Config, pow: &PowPolicy) -> crate::Result<usize> {
    let identity_fixed = IdentityUseCases::new(IdentityPowParams::from(pow.clone()))
        .apply_repairs(config, &identity::collect_repairs(config, pow))?;
    let structural_fixed = structural::apply_fixes(config);

    Ok(structural_fixed + identity_fixed)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    use crate::test_support;
    use crate::{
        Config, DomainIdentity, IdentityConfig, ListenConfig, ListenId, LogsConfig, NodeId,
        PeerConfig, PeerId, RuntimeFlavor, SignatureAlgorithm,
    };
    use veil_crypto as crypto;

    use super::{validate, validate_and_fix, validate_and_fix_with_policy, validate_with_policy};

    mod unit {
        use super::*;
        use crate::identity_policy::PowPolicy;

        #[test]
        fn reports_invalid_current_thread_worker_setting() {
            let mut config = Config::default();
            config.global.runtime_flavor = RuntimeFlavor::CurrentThread;
            config.global.worker_threads = Some(4);

            let report = validate(&config);
            assert_eq!(report.issues.len(), 1);
            assert_eq!(report.issues[0].key, "global.worker_threads");
        }

        #[test]
        fn fixes_supported_issues() {
            let mut config = Config::default();
            config.global.runtime_flavor = RuntimeFlavor::CurrentThread;
            config.global.worker_threads = Some(4);
            config.global.thread_name = Some("   ".to_owned());

            let report = validate_and_fix(&mut config).unwrap();
            assert_eq!(report.fixed, 2);
            assert!(report.is_valid());
            assert_eq!(config.global.worker_threads, None);
            assert_eq!(config.global.thread_name, None);
        }

        #[test]
        fn reports_invalid_identity_signature() {
            let identity = broken_signature_identity();
            let config = Config {
                identity: Some(identity),
                ..Config::default()
            };

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "identity_signature_valid")
            );
        }

        #[test]
        fn reports_invalid_identity_nonce() {
            let config = Config {
                identity: Some(test_support::identity_with_invalid_nonce()),
                ..Config::default()
            };

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "identity_nonce_has_leading_zero")
            );
        }

        #[test]
        fn reports_missing_node_id() {
            let config = Config {
                identity: Some(test_support::valid_identity()),
                ..Config::default()
            };

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "identity_node_id_matches_public_key")
            );
        }

        #[test]
        fn reports_duplicate_peer_ids() {
            let config = Config {
                peers: vec![
                    PeerConfig {
                        peer_id: PeerId::new(1),
                        public_key: "pub-a".to_owned(),
                        nonce: "AAAAAA==".to_owned(),
                        transport: "tcp://127.0.0.1:9000".to_owned(),
                        algo: Default::default(),
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        alt_uri: None,
                    },
                    PeerConfig {
                        peer_id: PeerId::new(1),
                        public_key: "pub-b".to_owned(),
                        nonce: "AAAAAA==".to_owned(),
                        transport: "tcp://127.0.0.1:9001".to_owned(),
                        algo: Default::default(),
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        alt_uri: None,
                    },
                ],
                ..Config::default()
            };

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "peers_peer_id_unique")
            );
        }

        #[test]
        fn reports_duplicate_listen_ids() {
            let config = Config {
                listen: vec![
                    ListenConfig {
                        id: ListenId::new(1),
                        transport: "tcp://127.0.0.1:9000".to_owned(),
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        advertise: None,
                        relay: None,
                        ..Default::default()
                    },
                    ListenConfig {
                        id: ListenId::new(1),
                        transport: "tcp://127.0.0.1:9001".to_owned(),
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        advertise: None,
                        relay: None,
                        ..Default::default()
                    },
                ],
                ..Config::default()
            };

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "listen_id_unique")
            );
        }

        #[test]
        fn reports_invalid_peer_and_listen_transport() {
            let mut config = Config::default();
            config.peers.push(PeerConfig {
                peer_id: PeerId::new(1),
                public_key: "pub".to_owned(),
                nonce: "AAAAAA==".to_owned(),
                transport: "://broken".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            });
            config.listen.push(ListenConfig {
                id: ListenId::new(1),
                transport: "sockstls://1.1.1.1:1080/2.2.2.2:443".to_owned(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                advertise: None,
                relay: None,
                ..Default::default()
            });

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "peers_transport_valid")
            );
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "listen_transport_supports_listener")
            );
        }

        #[test]
        fn reports_logs_file_without_path() {
            let mut config = Config::default();
            config.global.logs = LogsConfig::File;

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.code == "global_logs_file_requires_path")
            );
        }

        // ── update mechanism config validation ──────

        #[test]
        fn epic484_3_update_partial_config_with_only_urls_flagged_as_unsafe() {
            // Operator set manifest_urls but forgot expected_issuer_pk —
            // would mean fetched manifest's signature is verified
            // against… nothing. Catastrophic security hole; must be
            // surfaced loudly.
            let mut config = Config::default();
            config.update.manifest_urls = vec!["https://m.example/m".to_owned()];
            config.update.expected_issuer_pk = None;

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_partial_config_unsafe"),
                "must flag manifest_urls without issuer key as unsafe; got {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic484_3_update_partial_config_with_only_issuer_key_flagged_as_unsafe() {
            // Inverse: issuer key set but no URLs to fetch from = check
            // never engages but operator probably thought it would.
            // Also a misconfiguration that deserves a loud warning.
            let mut config = Config::default();
            config.update.manifest_urls = Vec::new();
            config.update.expected_issuer_pk = Some("0".repeat(64));

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_partial_config_unsafe"),
                "must flag issuer key without URLs as unsafe; got {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic484_3_update_both_or_neither_passes_validation() {
            // Both set → check enabled, no issue.
            let mut config = Config::default();
            config.update.manifest_urls = vec!["https://m.example/m".to_owned()];
            config.update.expected_issuer_pk = Some("0".repeat(64));
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_partial_config_unsafe"),
                "fully-configured update must NOT trigger partial-config issue: {:?}",
                report.issues,
            );

            // Neither set → feature disabled, no issue.
            let report = validate(&Config::default());
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_partial_config_unsafe"),
                "default config must NOT trigger update issues",
            );
        }

        #[test]
        fn epic484_3_update_http_url_rejected() {
            // Plain http:// would let an on-path attacker swap bytes
            // BEFORE signature verify even gets a chance. TLS verify
            // is the integrity-and-origin floor.
            let mut config = Config::default();
            config.update.manifest_urls = vec!["http://insecure.example/m".to_owned()];
            config.update.expected_issuer_pk = Some("0".repeat(64));

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_manifest_url_must_be_https"),
                "http:// URL must be flagged: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic483_6b_per_peer_bytes_below_1024_flagged() {
            // Misconfig (or operator typo) — anything below 1 KB/s
            // would prevent even small protocol traffic (handshake
            // exchanges, single keepalive frames are typically
            // 200-500 bytes) from completing. Validation flags so
            // operator can't accidentally brick connectivity.
            let mut config = Config::default();
            config.abuse.per_peer_bytes_per_sec = Some(512);
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "abuse_per_peer_bytes_per_sec_too_low"),
                "must flag sub-1024 bytes/sec rate: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic483_6b_per_peer_bytes_at_or_above_1024_passes() {
            let mut config = Config::default();
            config.abuse.per_peer_bytes_per_sec = Some(1024);
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "abuse_per_peer_bytes_per_sec_too_low"),
                "exactly-1024 must be accepted: {:?}",
                report.issues,
            );
            config.abuse.per_peer_bytes_per_sec = Some(65_536); // mobile profile default
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "abuse_per_peer_bytes_per_sec_too_low"),
                "mobile profile default 64 KB/s must be accepted: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic483_6b_per_peer_bytes_none_passes() {
            // Default (per-peer enforcement disabled) must NOT
            // trigger too-low rule — None is the intended "off"
            // sentinel, не a misconfig.
            let config = Config::default();
            assert!(config.abuse.per_peer_bytes_per_sec.is_none());
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "abuse_per_peer_bytes_per_sec_too_low"),
                "None (default) must NOT trigger too-low rule: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic488_1_session_max_age_below_60s_flagged() {
            // Misconfig (or malicious config push) с too-short
            // rotation interval would force connection-storm
            // (~once-a-second handshakes) — itself anomalous и
            // would dominate CPU/network cost. Floor matches
            // the runtime clamp в MIN_SESSION_MAX_AGE_SECS.
            let mut config = Config::default();
            config.session.max_age_secs = Some(30);
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "session_max_age_too_short"),
                "must flag sub-60s rotation interval: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic488_1_session_max_age_60s_or_more_passes() {
            let mut config = Config::default();
            config.session.max_age_secs = Some(60);
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "session_max_age_too_short"),
                "exactly-60s must be accepted: {:?}",
                report.issues,
            );
            config.session.max_age_secs = Some(1_800);
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "session_max_age_too_short"),
                "30 min must be accepted: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic488_1_session_max_age_none_passes() {
            // Default (rotation disabled) must NOT trigger the
            // too-short rule — None is the intended "rotation
            // off" sentinel, не a misconfig.
            let config = Config::default();
            assert!(config.session.max_age_secs.is_none());
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "session_max_age_too_short"),
                "None (default) must NOT trigger too-short: {:?}",
                report.issues,
            );
        }

        // ── [transport.rotation] validation ────────────────────────
        //
        // Mirrors the session.max_age_secs rules above, но для the
        // new range-based knobs (Q.7 audit batch — censor-evasion via
        // periodic TCP rotation).

        #[test]
        fn transport_rotation_default_passes_validation() {
            // Default (1800..3600) must be valid + не flag anything.
            let config = Config::default();
            let report = validate(&config);
            let rotation_issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| i.code.starts_with("transport_rotation_"))
                .collect();
            assert!(
                rotation_issues.is_empty(),
                "default rotation config must validate cleanly, got: {:?}",
                rotation_issues,
            );
        }

        #[test]
        fn transport_rotation_minus_one_both_disables_cleanly() {
            // -1/-1 = explicit disable. Must not trigger any too-short
            // OR partial-disable rule.
            let mut config = Config::default();
            config.transport.rotation.min_lifetime_secs = -1;
            config.transport.rotation.max_lifetime_secs = -1;
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code.starts_with("transport_rotation_")),
                "-1/-1 (disabled) must pass: {:?}",
                report.issues,
            );
        }

        #[test]
        fn transport_rotation_partial_disable_flagged() {
            // -1 в одном бо́ке + positive в другом — likely typo.
            let mut config = Config::default();
            config.transport.rotation.min_lifetime_secs = -1;
            config.transport.rotation.max_lifetime_secs = 3_600;
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "transport_rotation_partial_disable"),
                "mixed -1/positive must flag: {:?}",
                report.issues,
            );
        }

        #[test]
        fn transport_rotation_min_above_max_flagged() {
            let mut config = Config::default();
            config.transport.rotation.min_lifetime_secs = 7_200;
            config.transport.rotation.max_lifetime_secs = 3_600;
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "transport_rotation_min_above_max"),
                "min > max must flag: {:?}",
                report.issues,
            );
        }

        #[test]
        fn transport_rotation_below_60s_flagged() {
            // Same rationale as session.max_age_secs — sub-minute
            // rotation is itself anomalous.
            let mut config = Config::default();
            config.transport.rotation.min_lifetime_secs = 30;
            config.transport.rotation.max_lifetime_secs = 90;
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "transport_rotation_min_too_short"),
                "30s min must flag too-short: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic484_3_update_check_interval_below_60s_flagged() {
            // Misconfig (or malicious config push) with too-frequent
            // poll interval would DoS the operator's CDN with
            // thousands of nodes hitting it every second. 60s floor
            // matches the runtime clamp in MIN_CHECK_INTERVAL.
            let mut config = Config::default();
            config.update.manifest_urls = vec!["https://m.example/m".to_owned()];
            config.update.expected_issuer_pk = Some("0".repeat(64));
            config.update.check_interval_secs = Some(10);

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_check_interval_too_frequent"),
                "must flag sub-60s interval: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic484_3_update_check_interval_60s_or_more_passes() {
            let mut config = Config::default();
            config.update.manifest_urls = vec!["https://m.example/m".to_owned()];
            config.update.expected_issuer_pk = Some("0".repeat(64));
            config.update.check_interval_secs = Some(60);
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_check_interval_too_frequent"),
                "exactly-60s must be accepted: {:?}",
                report.issues,
            );

            config.update.check_interval_secs = Some(86400); // 24h
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_check_interval_too_frequent"),
                "24h must be accepted: {:?}",
                report.issues,
            );
        }

        #[test]
        fn epic484_3_update_mixed_https_and_http_still_flagged() {
            // ANY non-https URL must trigger the rule, even when most
            // are valid — partial enforcement would let a censor poison
            // one entry to skip TLS verification on that endpoint.
            let mut config = Config::default();
            config.update.manifest_urls = vec![
                "https://cdn1.example/m".to_owned(),
                "http://cdn2.example/m".to_owned(),
                "https://cdn3.example/m".to_owned(),
            ];
            config.update.expected_issuer_pk = Some("0".repeat(64));

            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "update_manifest_url_must_be_https"),
                "single http:// in list must still flag: {:?}",
                report.issues,
            );
        }

        #[test]
        fn validate_with_policy_uses_custom_difficulty_message() {
            let config = Config {
                identity: Some(test_support::identity_with_invalid_nonce()),
                ..Config::default()
            };

            let report = validate_with_policy(
                &config,
                &PowPolicy {
                    difficulty: 20,
                    ..PowPolicy::canonical()
                },
            );

            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.message.contains("20 leading zero bits"))
            );
        }
    }

    mod integration_pow {
        use super::*;
        use crate::identity_policy::PowPolicy;

        #[test]
        fn fix_regenerates_invalid_identity_signature() {
            let mut config = Config {
                identity: Some(broken_signature_identity()),
                ..Config::default()
            };

            let report = validate_and_fix(&mut config).unwrap();
            assert!(report.fixed >= 1);
            assert!(crate::identity::identity_signature_is_valid(
                &DomainIdentity::from_config(config.identity.as_ref().unwrap()).unwrap()
            ));
        }

        #[test]
        fn fix_recomputes_invalid_identity_nonce() {
            let mut config = Config {
                identity: Some(test_support::identity_with_invalid_nonce()),
                ..Config::default()
            };

            let report = validate_and_fix(&mut config).unwrap();
            assert!(report.fixed >= 1);
            let identity = DomainIdentity::from_config(config.identity.as_ref().unwrap()).unwrap();
            assert!(crate::identity::identity_nonce_meets_difficulty(
                &identity,
                crypto::DEFAULT_POW_DIFFICULTY
            ));
        }

        #[test]
        fn fix_generates_missing_node_id() {
            let mut config = Config {
                identity: Some(test_support::valid_identity()),
                ..Config::default()
            };

            let report = validate_and_fix(&mut config).unwrap();
            assert!(report.fixed >= 1);

            let identity = config.identity.as_ref().unwrap();
            let expected = NodeId::from_public_key(identity.algo, &identity.public_key).unwrap();
            assert_eq!(identity.node_id, Some(expected));
        }

        #[test]
        fn validate_and_fix_with_policy_uses_custom_difficulty() {
            let mut config = Config {
                identity: Some(test_support::identity_with_nonce_below(8)),
                ..Config::default()
            };

            let policy = PowPolicy {
                difficulty: 8,
                timeout: Duration::from_secs(2),
                threads: 1,
            };

            let report = validate_and_fix_with_policy(&mut config, &policy).unwrap();
            assert!(report.fixed >= 1);

            let identity = DomainIdentity::from_config(config.identity.as_ref().unwrap()).unwrap();
            assert!(crate::identity::identity_nonce_meets_difficulty(
                &identity,
                policy.difficulty
            ));
        }

        #[test]
        fn fix_recomputes_node_id_after_identity_regeneration() {
            let mut config = Config {
                identity: Some(broken_signature_identity()),
                ..Config::default()
            };
            config.identity.as_mut().unwrap().node_id = Some(
                NodeId::from_public_key(
                    SignatureAlgorithm::Ed25519,
                    &test_support::ed25519_keypair().public_key,
                )
                .unwrap(),
            );

            validate_and_fix(&mut config).unwrap();

            let identity = config.identity.as_ref().unwrap();
            let expected = NodeId::from_public_key(identity.algo, &identity.public_key).unwrap();
            assert_eq!(identity.node_id, Some(expected));
        }
    }

    // ── new field validation tests ──────────────────────────────────

    mod epic_85 {
        use super::*;
        use crate::{BootstrapPeer, SessionConfig};

        #[test]
        fn partition_score_threshold_too_high() {
            let mut config = Config::default();
            config.routing.partition_score_threshold = 1.5;
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "partition_score_threshold_out_of_range"),
                "expected partition_score_threshold_out_of_range issue, got {:?}",
                report.issues
            );
        }

        #[test]
        fn partition_score_threshold_negative() {
            let mut config = Config::default();
            config.routing.partition_score_threshold = -0.1;
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "partition_score_threshold_out_of_range"),
                "expected partition_score_threshold_out_of_range issue"
            );
        }

        #[test]
        fn partition_score_threshold_valid() {
            let mut config = Config::default();
            config.routing.partition_score_threshold = 0.2;
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "partition_score_threshold_out_of_range"),
                "no issue expected for valid threshold"
            );
        }

        #[test]
        fn keepalive_exceeds_idle_timeout_flagged() {
            let config = Config {
                session: SessionConfig {
                    keepalive_interval_secs: 5,
                    idle_timeout_secs: 3,
                    ..SessionConfig::default()
                },
                ..Config::default()
            };
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "keepalive_exceeds_idle_timeout"),
                "expected keepalive_exceeds_idle_timeout issue, got {:?}",
                report.issues
            );
        }

        #[test]
        fn keepalive_less_than_idle_ok() {
            let config = Config {
                session: SessionConfig {
                    keepalive_interval_secs: 1,
                    idle_timeout_secs: 4,
                    ..SessionConfig::default()
                },
                ..Config::default()
            };
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "keepalive_exceeds_idle_timeout"),
                "no issue expected when keepalive < idle"
            );
        }

        #[test]
        fn bootstrap_peer_invalid_pubkey_flagged() {
            let mut config = Config::default();
            config.bootstrap_peers.push(BootstrapPeer {
                transport: "tcp://127.0.0.1:9000".to_owned(),
                public_key: "not-valid-base64!!!".to_owned(),
                nonce: crate::default_nonce_base64(),
                algo: Default::default(),
                tls_cert: None,
                tls_ca_cert: None,
            });
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "bootstrap_peer_invalid_public_key"),
                "expected bootstrap_peer_invalid_public_key issue"
            );
        }

        #[test]
        fn bootstrap_peer_invalid_transport_flagged() {
            let mut config = Config::default();
            config.bootstrap_peers.push(BootstrapPeer {
                transport: "not-a-uri".to_owned(),
                public_key: crate::test_support::ed25519_keypair().public_key,
                nonce: crate::default_nonce_base64(),
                algo: Default::default(),
                tls_cert: None,
                tls_ca_cert: None,
            });
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "bootstrap_peer_invalid_transport"),
                "expected bootstrap_peer_invalid_transport issue"
            );
        }

        #[test]
        fn bootstrap_peer_valid() {
            let mut config = Config::default();
            config.bootstrap_peers.push(BootstrapPeer {
                transport: "tcp://127.0.0.1:9000".to_owned(),
                public_key: crate::test_support::ed25519_keypair().public_key,
                nonce: crate::default_nonce_base64(),
                algo: Default::default(),
                tls_cert: None,
                tls_ca_cert: None,
            });
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "bootstrap_peer_invalid_public_key"),
                "no issue expected for valid bootstrap peer pubkey"
            );
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "bootstrap_peer_invalid_transport"),
                "no issue expected for valid bootstrap peer transport"
            );
        }

        /// Audit L-22: a Falcon-512 bootstrap peer (897-byte pubkey) must NOT be
        /// flagged invalid. The check previously hard-coded Ed25519, so a valid
        /// Falcon-512 peer failed the 32-byte length check and blocked startup.
        #[test]
        fn bootstrap_peer_falcon512_pubkey_valid_l22() {
            let mut config = Config::default();
            config.bootstrap_peers.push(BootstrapPeer {
                transport: "tcp://127.0.0.1:9000".to_owned(),
                public_key: crate::test_support::falcon512_keypair().public_key,
                nonce: crate::default_nonce_base64(),
                algo: SignatureAlgorithm::Falcon512,
                tls_cert: None,
                tls_ca_cert: None,
            });
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "bootstrap_peer_invalid_public_key"),
                "a valid Falcon-512 bootstrap peer pubkey must not be flagged"
            );
        }

        // ── relay validation ────────────────────────────────────────

        #[test]
        fn listen_relay_invalid_base64_flagged() {
            let mut config = Config::default();
            config.listen.push(ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: Some("not-valid-base64!!!".to_owned()),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            });
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "listen_relay_invalid_node_id"),
                "expected listen_relay_invalid_node_id, got {:?}",
                report.issues
            );
        }

        #[test]
        fn listen_relay_wrong_length_flagged() {
            let mut config = Config::default();
            // Valid base64 but only 16 bytes (not 32).
            let short = B64.encode([0u8; 16]);
            config.listen.push(ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: Some(short),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            });
            let report = validate(&config);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == "listen_relay_invalid_node_id"),
                "expected listen_relay_invalid_node_id for short relay id"
            );
        }

        #[test]
        fn listen_relay_valid_32_bytes_ok() {
            let mut config = Config::default();
            let valid = B64.encode([0x42u8; 32]);
            config.listen.push(ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: Some(valid),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            });
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "listen_relay_invalid_node_id"),
                "no issue expected for valid 32-byte relay id"
            );
        }

        #[test]
        fn listen_relay_absent_ok() {
            let mut config = Config::default();
            config.listen.push(ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: None,
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            });
            let report = validate(&config);
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|i| i.code == "listen_relay_invalid_node_id"),
                "no issue when relay is absent"
            );
        }
    }

    fn broken_signature_identity() -> IdentityConfig {
        let valid = test_support::valid_identity();
        let mismatched_public = test_support::ed25519_keypair().public_key;

        IdentityConfig {
            algo: SignatureAlgorithm::Ed25519,
            role: Default::default(),
            public_key: mismatched_public,
            private_key: valid.private_key,
            nonce: valid.nonce,
            node_id: valid.node_id,
            key_passphrase: None,
            key_passphrase_file: None,
            key_passphrase_prompt: false,
            lazy_mining: true,
            max_lazy_difficulty: 64,
        }
    }
}
