use std::collections::HashSet;

use crate::{Config, LogsConfig, NodeId, RuntimeFlavor};
use veil_crypto::Base64PublicKey;
use veil_transport::{TransportRegistry, TransportUri};

use super::report::ValidationIssue;

pub struct ValidationRule {
    pub code: &'static str,
    pub key: &'static str,
    pub message: &'static str,
    pub check: fn(&Config) -> bool,
    pub fix: Option<fn(&mut Config) -> bool>,
}

pub const VALIDATION_RULES: &[ValidationRule] = &[
    ValidationRule {
        code: "current_thread_without_worker_threads",
        key: "global.worker_threads",
        message: "must not be set when runtime_flavor is current_thread",
        check: current_thread_without_worker_threads,
        fix: Some(fix_current_thread_without_worker_threads),
    },
    ValidationRule {
        code: "positive_worker_threads",
        key: "global.worker_threads",
        message: "must be greater than zero",
        check: positive_worker_threads,
        fix: Some(fix_positive_worker_threads),
    },
    ValidationRule {
        code: "positive_max_blocking_threads",
        key: "global.max_blocking_threads",
        message: "must be greater than zero",
        check: positive_max_blocking_threads,
        fix: Some(fix_positive_max_blocking_threads),
    },
    ValidationRule {
        code: "positive_thread_keep_alive_ms",
        key: "global.thread_keep_alive_ms",
        message: "must be greater than zero",
        check: positive_thread_keep_alive_ms,
        fix: Some(fix_positive_thread_keep_alive_ms),
    },
    ValidationRule {
        code: "non_empty_thread_name",
        key: "global.thread_name",
        message: "must not be empty or whitespace-only",
        check: non_empty_thread_name,
        fix: Some(fix_non_empty_thread_name),
    },
    ValidationRule {
        code: "positive_thread_stack_size",
        key: "global.thread_stack_size",
        message: "must be greater than zero",
        check: positive_thread_stack_size,
        fix: Some(fix_positive_thread_stack_size),
    },
    ValidationRule {
        code: "global_admin_socket_is_unix_or_tcp_transport",
        key: "global.admin_socket",
        message: "must be a unix://, tcp://127.0.0.1, or pipe://NAME transport URI",
        check: invalid_admin_socket,
        fix: None,
    },
    ValidationRule {
        code: "global_logs_file_requires_path",
        key: "global.log_file",
        message: "must be set when global.logs is file",
        check: missing_log_file,
        fix: None,
    },
    ValidationRule {
        code: "global_logs_stderr_clears_log_file",
        key: "global.log_file",
        message: "must not be set when global.logs is stderr",
        check: unexpected_log_file,
        fix: Some(fix_unexpected_log_file),
    },
    ValidationRule {
        code: "identity_node_id_matches_public_key",
        key: "identity.node_id",
        message: "must equal blake3(public_key) as a 32-byte hex digest",
        check: invalid_node_id,
        fix: Some(fix_invalid_node_id),
    },
    ValidationRule {
        code: "peers_peer_id_unique",
        key: "peers.peer_id",
        message: "must be unique",
        check: duplicate_peer_ids,
        fix: None,
    },
    ValidationRule {
        code: "peers_transport_valid",
        key: "peers.transport",
        message: "must be a valid transport URI",
        check: invalid_peer_transport,
        fix: None,
    },
    ValidationRule {
        code: "peers_tls_identity_complete",
        key: "peers.tls_cert",
        message: "tls_cert and tls_key must be set together",
        check: incomplete_peer_tls_identity,
        fix: None,
    },
    ValidationRule {
        code: "peers_tls_overrides_require_secure_transport",
        key: "peers.transport",
        message: "tls_cert, tls_key and tls_ca_cert are only supported for tls://, wss:// and quic:// peers",
        check: peer_tls_overrides_on_unsupported_transport,
        fix: None,
    },
    ValidationRule {
        code: "listen_id_unique",
        key: "listen.id",
        message: "must be unique",
        check: duplicate_listen_ids,
        fix: None,
    },
    ValidationRule {
        code: "listen_transport_valid",
        key: "listen.transport",
        message: "must be a valid transport URI",
        check: invalid_listen_transport,
        fix: None,
    },
    ValidationRule {
        code: "listen_transport_supports_listener",
        key: "listen.transport",
        message: "must use a transport scheme that supports listen/bind",
        check: listen_transport_without_listener,
        fix: None,
    },
    ValidationRule {
        code: "listen_tls_identity_complete",
        key: "listen.tls_cert",
        message: "tls_cert and tls_key must be set together",
        check: incomplete_listen_tls_identity,
        fix: None,
    },
    ValidationRule {
        code: "listen_tls_overrides_require_secure_transport",
        key: "listen.transport",
        message: "tls_cert, tls_key and tls_ca_cert are only supported for tls://, wss:// and quic:// listeners",
        check: listen_tls_overrides_on_unsupported_transport,
        fix: None,
    },
    ValidationRule {
        code: "metrics_listen_valid",
        key: "metrics.listen",
        message: "must be a valid transport URI",
        check: invalid_metrics_transport,
        fix: None,
    },
    ValidationRule {
        code: "metrics_transport_supports_listener",
        key: "metrics.listen",
        message: "must use a transport scheme that supports listen/bind",
        check: metrics_transport_without_listener,
        fix: None,
    },
    // ── new field validations ───────────────────────────────────────
    ValidationRule {
        code: "partition_score_threshold_out_of_range",
        key: "routing.partition_score_threshold",
        message: "must be in [0.0, 1.0]",
        check: partition_score_threshold_out_of_range,
        fix: None,
    },
    // iterative-DHT fallback bounds. Outside these
    // ranges the fallback either pile-drives the response path (timeout too
    // short → constant misses) or stalls the miss-handler indefinitely
    // (too long → app-layer can't tell route-discovery is hung).
    ValidationRule {
        code: "dht_fallback_timeout_out_of_range",
        key: "routing.dht_fallback_timeout_ms",
        message: "must be in [1000, 60000] ms",
        check: dht_fallback_timeout_out_of_range,
        fix: None,
    },
    ValidationRule {
        code: "dht_fallback_backpressure_threshold_out_of_range",
        key: "routing.dht_fallback_backpressure_threshold_pct",
        message: "must be in [1, 100] %",
        check: dht_fallback_backpressure_threshold_out_of_range,
        fix: None,
    },
    ValidationRule {
        code: "dht_fallback_priority_mult_out_of_range",
        key: "routing.dht_fallback_priority_mult",
        message: "both multipliers must be in [10, 1000] (0.1× to 10×)",
        check: dht_fallback_priority_mult_out_of_range,
        fix: None,
    },
    ValidationRule {
        code: "keepalive_exceeds_idle_timeout",
        key: "session.keepalive_interval_secs",
        message: "keepalive_interval_secs must be less than idle_timeout_secs when both are non-zero",
        check: keepalive_exceeds_idle_timeout,
        fix: None,
    },
    ValidationRule {
        code: "bootstrap_peer_invalid_public_key",
        key: "bootstrap_peers[].public_key",
        message: "must be valid base64 encoding a 32-byte ed25519 public key",
        check: bootstrap_peer_invalid_public_key,
        fix: None,
    },
    ValidationRule {
        code: "bootstrap_peer_invalid_transport",
        key: "bootstrap_peers[].transport",
        message: "must be a valid transport URI",
        check: bootstrap_peer_invalid_transport,
        fix: None,
    },
    // ── NAT traversal ───────────────────────────────────────────────
    ValidationRule {
        code: "nat_punch_timeout_zero",
        key: "nat.punch_timeout_ms",
        message: "must be greater than zero",
        check: nat_punch_timeout_zero,
        fix: None,
    },
    // ── advertise / relay validation ────────────────────────────────
    ValidationRule {
        code: "listen_relay_invalid_node_id",
        key: "listen[].relay",
        message: "must be valid base64 encoding a 32-byte node id",
        check: listen_relay_invalid_node_id,
        fix: None,
    },
    // ── upper bound config validation ───────────────────────────────
    ValidationRule {
        code: "keepalive_interval_too_large",
        key: "session.keepalive_interval_secs",
        message: "must be at most 3600 seconds (1 hour)",
        check: keepalive_interval_too_large,
        fix: None,
    },
    ValidationRule {
        code: "idle_timeout_too_large",
        key: "session.idle_timeout_secs",
        message: "must be at most 86400 seconds (24 hours)",
        check: idle_timeout_too_large,
        fix: None,
    },
    ValidationRule {
        code: "punch_timeout_too_large",
        key: "nat.punch_timeout_ms",
        message: "must be at most 30000 ms (30 seconds)",
        check: punch_timeout_too_large,
        fix: None,
    },
    ValidationRule {
        code: "dht_cleanup_interval_zero",
        key: "dht.cleanup_interval_secs",
        message: "must be greater than zero (zero would panic on interval creation)",
        check: dht_cleanup_interval_zero,
        fix: None,
    },
    // ── signed update mechanism ──────────────────────────────────
    ValidationRule {
        code: "update_partial_config_unsafe",
        key: "update.expected_issuer_pk",
        message: "manifest_urls and expected_issuer_pk must be set together; setting one without the other is a security hole (would accept ANY signature OR have no fetch target)",
        check: update_partial_config_unsafe,
        fix: None,
    },
    ValidationRule {
        code: "update_manifest_url_must_be_https",
        key: "update.manifest_urls",
        message: "every manifest URL must start with https:// — http:// would let an on-path attacker swap the bytes before signature verification",
        check: update_manifest_url_must_be_https,
        fix: None,
    },
    ValidationRule {
        code: "update_check_interval_too_frequent",
        key: "update.check_interval_secs",
        message: "must be at least 60 seconds — shorter intervals could DoS the operator's update CDN with thousands of nodes polling every second",
        check: update_check_interval_too_frequent,
        fix: None,
    },
    // ── connection-rotation interval ────────────────────────────
    ValidationRule {
        code: "session_max_age_too_short",
        key: "session.max_age_secs",
        message: "must be at least 60 seconds — rotating connections faster than once-a-minute is itself anomalous (real HTTPS sessions don't rotate that fast) AND would dominate connection cost",
        check: session_max_age_too_short,
        fix: None,
    },
    ValidationRule {
        code: "transport_rotation_min_too_short",
        key: "transport.rotation.min_lifetime_secs",
        message: "must be at least 60 seconds (or -1 to disable rotation) — rotating connections faster than once-a-minute is itself anomalous + dominates handshake cost",
        check: transport_rotation_min_too_short,
        fix: None,
    },
    ValidationRule {
        code: "transport_rotation_max_too_short",
        key: "transport.rotation.max_lifetime_secs",
        message: "must be at least 60 seconds (or -1 to disable rotation)",
        check: transport_rotation_max_too_short,
        fix: None,
    },
    ValidationRule {
        code: "transport_rotation_min_above_max",
        key: "transport.rotation.min_lifetime_secs",
        message: "min_lifetime_secs must be ≤ max_lifetime_secs when both are positive — a min > max range cannot sample a deadline",
        check: transport_rotation_min_above_max,
        fix: None,
    },
    ValidationRule {
        code: "transport_rotation_partial_disable",
        key: "transport.rotation.min_lifetime_secs",
        message: "to disable rotation set BOTH min_lifetime_secs and max_lifetime_secs to -1, or leave both positive — a mismatched pair (one -1, the other positive) is a likely config typo",
        check: transport_rotation_partial_disable,
        fix: None,
    },
    // ── b: per-peer byte-rate ─────────────────────────────────────
    ValidationRule {
        code: "abuse_per_peer_bytes_per_sec_too_low",
        key: "abuse.per_peer_bytes_per_sec",
        message: "must be at least 1024 bytes/sec when set — anything lower would prevent even small protocol traffic (handshakes, single keepalive frames) from completing successfully",
        check: abuse_per_peer_bytes_per_sec_too_low,
        fix: None,
    },
    // ── P-Net: private-network membership-cert config validation ──
    ValidationRule {
        code: "network_private_requires_network_id",
        key: "network.network_id",
        message: "must be set when network.mode = \"private\" — a private veil must have a stable identifier the membership cert binds to",
        check: network_private_missing_network_id,
        fix: None,
    },
    ValidationRule {
        code: "network_private_requires_owner_pubkey",
        key: "network.owner_pubkey",
        message: "must be set when network.mode = \"private\" — the membership cert is verified against this public key",
        check: network_private_missing_owner_pubkey,
        fix: None,
    },
    ValidationRule {
        code: "network_private_requires_owner_algo",
        key: "network.owner_algo",
        message: "must be set when network.mode = \"private\" — signature dispatch needs to know the owner's algorithm",
        check: network_private_missing_owner_algo,
        fix: None,
    },
    ValidationRule {
        code: "network_private_requires_membership_cert",
        key: "network.membership_cert",
        message: "must be set when network.mode = \"private\" — node needs its own membership cert to present at handshake time",
        check: network_private_missing_membership_cert,
        fix: None,
    },
    ValidationRule {
        code: "network_id_hex_64_chars",
        key: "network.network_id",
        message: "must be exactly 64 lowercase hex characters (32-byte network identifier)",
        check: network_id_wrong_format,
        fix: None,
    },
];

pub fn collect_issues(config: &Config) -> Vec<ValidationIssue> {
    VALIDATION_RULES
        .iter()
        .filter(|rule| (rule.check)(config))
        .map(|rule| ValidationIssue {
            code: rule.code,
            key: rule.key,
            message: rule.message.to_owned(),
            can_fix: rule.fix.is_some(),
        })
        .collect()
}

pub fn apply_fixes(config: &mut Config) -> usize {
    let mut count = 0;
    for rule in VALIDATION_RULES {
        if let Some(fix) = rule.fix
            && (rule.check)(config)
            && fix(config)
        {
            count += 1;
        }
    }
    count
}

fn current_thread_without_worker_threads(config: &Config) -> bool {
    config.global.runtime_flavor == RuntimeFlavor::CurrentThread
        && config.global.worker_threads.is_some()
}

fn positive_worker_threads(config: &Config) -> bool {
    config.global.worker_threads == Some(0)
}

fn positive_max_blocking_threads(config: &Config) -> bool {
    config.global.max_blocking_threads == Some(0)
}

fn positive_thread_keep_alive_ms(config: &Config) -> bool {
    config.global.thread_keep_alive_ms == Some(0)
}

fn non_empty_thread_name(config: &Config) -> bool {
    config
        .global
        .thread_name
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
}

fn positive_thread_stack_size(config: &Config) -> bool {
    config.global.thread_stack_size == Some(0)
}

fn invalid_admin_socket(config: &Config) -> bool {
    let Some(value) = config.global.admin_socket.as_deref() else {
        return false;
    };
    // Strip optional `?runtime_dir=...` query — it's admin-layer metadata
    // not part of the transport URI proper.
    let uri_body = value.split('?').next().unwrap_or(value);

    // `pipe://LEAF` (Windows NamedPipe). TransportUri doesn't
    // know about NamedPipes; admin parses this scheme itself. Accept any
    // non-empty alphanumeric-ish leaf — actual creation is gated by
    // `bind_named_pipe` at runtime.
    if let Some(rest) = uri_body.strip_prefix("pipe://") {
        let leaf = rest.split('/').next().unwrap_or("");
        return leaf.is_empty() || leaf.contains(':') || leaf.contains('\\');
    }

    match TransportUri::parse(uri_body) {
        Ok(TransportUri::Unix { .. }) => false,
        Ok(TransportUri::Tcp { host, .. }) => {
            // Only allow loopback binds — admin over a publicly-reachable
            // port would let the token-auth handshake be probed from the
            // network. The runtime binds `127.0.0.1` literally so we require
            // the host to match.
            host != "127.0.0.1" && host != "::1" && host != "localhost"
        }
        _ => true,
    }
}

fn missing_log_file(config: &Config) -> bool {
    config.global.logs == LogsConfig::File && config.global.log_file.is_none()
}

fn unexpected_log_file(config: &Config) -> bool {
    config.global.logs == LogsConfig::Stderr && config.global.log_file.is_some()
}

fn invalid_node_id(config: &Config) -> bool {
    config.identity.as_ref().is_some_and(|identity| {
        let expected = NodeId::from_public_key(identity.algo, &identity.public_key);
        match (identity.node_id, expected) {
            (Some(current), Ok(expected)) => current != expected,
            (None, Ok(_)) => true,
            _ => false,
        }
    })
}

fn duplicate_peer_ids(config: &Config) -> bool {
    has_duplicate_ids(config.peers.iter().map(|peer| peer.peer_id))
}

fn invalid_peer_transport(config: &Config) -> bool {
    config
        .peers
        .iter()
        .any(|peer| TransportUri::parse(&peer.transport).is_err())
}

fn duplicate_listen_ids(config: &Config) -> bool {
    has_duplicate_ids(config.listen.iter().map(|listen| listen.id))
}

fn incomplete_peer_tls_identity(config: &Config) -> bool {
    config
        .peers
        .iter()
        .any(|peer| peer.tls_cert.is_some() != peer.tls_key.is_some())
}

fn invalid_listen_transport(config: &Config) -> bool {
    config
        .listen
        .iter()
        .any(|listen| TransportUri::parse(&listen.transport).is_err())
}

fn incomplete_listen_tls_identity(config: &Config) -> bool {
    config
        .listen
        .iter()
        .any(|listen| listen.tls_cert.is_some() != listen.tls_key.is_some())
}

fn listen_transport_without_listener(config: &Config) -> bool {
    let registry = TransportRegistry::with_defaults();
    config
        .listen
        .iter()
        .any(|listen| listener_capability(&registry, &listen.transport) == Some(false))
}

fn peer_tls_overrides_on_unsupported_transport(config: &Config) -> bool {
    config.peers.iter().any(|peer| {
        has_tls_overrides(
            peer.tls_cert.as_deref(),
            peer.tls_key.as_deref(),
            peer.tls_ca_cert.as_deref(),
        ) && !secure_tls_override_transport(&peer.transport)
    })
}

fn listen_tls_overrides_on_unsupported_transport(config: &Config) -> bool {
    config.listen.iter().any(|listen| {
        has_tls_overrides(
            listen.tls_cert.as_deref(),
            listen.tls_key.as_deref(),
            listen.tls_ca_cert.as_deref(),
        ) && !secure_tls_override_transport(&listen.transport)
    })
}

fn invalid_metrics_transport(config: &Config) -> bool {
    config
        .metrics
        .as_ref()
        .is_some_and(|metrics| TransportUri::parse(&metrics.listen).is_err())
}

fn metrics_transport_without_listener(config: &Config) -> bool {
    let registry = TransportRegistry::with_defaults();
    config
        .metrics
        .as_ref()
        .is_some_and(|metrics| listener_capability(&registry, &metrics.listen) == Some(false))
}

fn has_tls_overrides(cert: Option<&str>, key: Option<&str>, ca_cert: Option<&str>) -> bool {
    cert.is_some() || key.is_some() || ca_cert.is_some()
}

fn secure_tls_override_transport(transport: &str) -> bool {
    matches!(
        TransportUri::parse(transport),
        Ok(TransportUri::Tls { .. } | TransportUri::Wss { .. } | TransportUri::Quic { .. })
    )
}

fn fix_current_thread_without_worker_threads(config: &mut Config) -> bool {
    config.global.worker_threads = None;
    true
}

fn fix_positive_worker_threads(config: &mut Config) -> bool {
    config.global.worker_threads = None;
    true
}

fn fix_positive_max_blocking_threads(config: &mut Config) -> bool {
    config.global.max_blocking_threads = None;
    true
}

fn fix_positive_thread_keep_alive_ms(config: &mut Config) -> bool {
    config.global.thread_keep_alive_ms = None;
    true
}

fn fix_non_empty_thread_name(config: &mut Config) -> bool {
    config.global.thread_name = None;
    true
}

fn fix_positive_thread_stack_size(config: &mut Config) -> bool {
    config.global.thread_stack_size = None;
    true
}

fn fix_unexpected_log_file(config: &mut Config) -> bool {
    config.global.log_file = None;
    true
}

fn fix_invalid_node_id(config: &mut Config) -> bool {
    let Some(identity) = config.identity.as_mut() else {
        return false;
    };

    let Ok(expected) = NodeId::from_public_key(identity.algo, &identity.public_key) else {
        return false;
    };

    if identity.node_id == Some(expected) {
        false
    } else {
        identity.node_id = Some(expected);
        true
    }
}

fn has_duplicate_ids<T>(mut values: impl Iterator<Item = T>) -> bool
where
    T: Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    values.any(|value| !seen.insert(value))
}

fn listener_capability(registry: &TransportRegistry, transport: &str) -> Option<bool> {
    let uri = TransportUri::parse(transport).ok()?;
    let transport = registry.get(uri.scheme()).ok()?;
    Some(transport.capabilities().listener)
}

// ── new check helpers ────────────────────────────────────────────────

fn partition_score_threshold_out_of_range(config: &Config) -> bool {
    let t = config.routing.partition_score_threshold;
    !(0.0..=1.0).contains(&t)
}

fn dht_fallback_timeout_out_of_range(config: &Config) -> bool {
    let t = config.routing.dht_fallback_timeout_ms;
    !(1000..=60_000).contains(&t)
}

fn dht_fallback_backpressure_threshold_out_of_range(config: &Config) -> bool {
    let p = config.routing.dht_fallback_backpressure_threshold_pct;
    !(1..=100).contains(&p)
}

fn dht_fallback_priority_mult_out_of_range(config: &Config) -> bool {
    let [int_mult, bg_mult] = config.routing.dht_fallback_priority_mult;
    !(10..=1000).contains(&int_mult) || !(10..=1000).contains(&bg_mult)
}

fn keepalive_exceeds_idle_timeout(config: &Config) -> bool {
    let ka = config.session.keepalive_interval_secs;
    let idle = config.session.idle_timeout_secs;
    ka > 0 && idle > 0 && ka >= idle
}

fn bootstrap_peer_invalid_public_key(config: &Config) -> bool {
    config.bootstrap_peers.iter().any(|bp| {
        // Audit L-22: validate against the peer's DECLARED algorithm, not a
        // hard-coded Ed25519. A Falcon-512 bootstrap peer (897-byte pubkey,
        // algo="falcon512" — settable on BootstrapPeer and accepted by the
        // invite decoder) would otherwise fail the 32-byte Ed25519 check, the
        // rule would fire, and the (non-fixable) validation error would block
        // node startup for a legitimately-configured Falcon-512 peer. Mirrors
        // how the identity validators already respect the configured algo.
        Base64PublicKey::new(bp.algo, &bp.public_key).is_err()
    })
}

fn bootstrap_peer_invalid_transport(config: &Config) -> bool {
    config
        .bootstrap_peers
        .iter()
        .any(|bp| TransportUri::parse(&bp.transport).is_err())
}

fn listen_relay_invalid_node_id(config: &Config) -> bool {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    config.listen.iter().any(|listen| {
        listen.relay.as_deref().is_some_and(|relay| {
            STANDARD
                .decode(relay)
                .map_or(true, |bytes| bytes.len() != 32)
        })
    })
}

fn nat_punch_timeout_zero(config: &Config) -> bool {
    config.nat.punch_timeout_ms == 0
}

fn keepalive_interval_too_large(config: &Config) -> bool {
    config.session.keepalive_interval_secs > 3_600
}

fn idle_timeout_too_large(config: &Config) -> bool {
    config.session.idle_timeout_secs > 86_400
}

fn punch_timeout_too_large(config: &Config) -> bool {
    config.nat.punch_timeout_ms > 30_000
}

fn dht_cleanup_interval_zero(config: &Config) -> bool {
    config.dht.cleanup_interval_secs == 0
}

fn update_partial_config_unsafe(config: &Config) -> bool {
    let has_urls = !config.update.manifest_urls.is_empty();
    let has_key = config.update.expected_issuer_pk.is_some();
    has_urls != has_key
}

fn update_manifest_url_must_be_https(config: &Config) -> bool {
    config
        .update
        .manifest_urls
        .iter()
        // Scheme is case-insensitive (RFC 3986); match the fetch layer
        // which compares case-insensitively.
        .any(|url| !url.to_ascii_lowercase().starts_with("https://"))
}

fn update_check_interval_too_frequent(config: &Config) -> bool {
    matches!(config.update.check_interval_secs, Some(n) if n < 60)
}

fn session_max_age_too_short(config: &Config) -> bool {
    matches!(config.session.max_age_secs, Some(n) if n < 60)
}

fn transport_rotation_min_too_short(config: &Config) -> bool {
    let v = config.transport.rotation.min_lifetime_secs;
    // `-1` (disabled) is OK; any other negative value is a typo (only
    // `-1` is the official sentinel).  Positive values must be ≥ 60.
    v != -1 && v < 60
}

fn transport_rotation_max_too_short(config: &Config) -> bool {
    let v = config.transport.rotation.max_lifetime_secs;
    v != -1 && v < 60
}

fn transport_rotation_min_above_max(config: &Config) -> bool {
    let min = config.transport.rotation.min_lifetime_secs;
    let max = config.transport.rotation.max_lifetime_secs;
    min > 0 && max > 0 && min > max
}

fn transport_rotation_partial_disable(config: &Config) -> bool {
    let min_disabled = config.transport.rotation.min_lifetime_secs == -1;
    let max_disabled = config.transport.rotation.max_lifetime_secs == -1;
    min_disabled != max_disabled
}

fn abuse_per_peer_bytes_per_sec_too_low(config: &Config) -> bool {
    matches!(config.abuse.per_peer_bytes_per_sec, Some(n) if n < 1024)
}

// ── P-Net Phase 1c: private-network config validation ──────────────

fn is_private(config: &Config) -> bool {
    matches!(
        config.network.as_ref().map(|n| n.mode),
        Some(veil_types::NetworkMode::Private)
    )
}

fn network_private_missing_network_id(config: &Config) -> bool {
    is_private(config)
        && config
            .network
            .as_ref()
            .is_some_and(|n| n.network_id.is_none())
}

fn network_private_missing_owner_pubkey(config: &Config) -> bool {
    is_private(config)
        && config
            .network
            .as_ref()
            .is_some_and(|n| n.owner_pubkey.is_none())
}

fn network_private_missing_owner_algo(config: &Config) -> bool {
    is_private(config)
        && config
            .network
            .as_ref()
            .is_some_and(|n| n.owner_algo.is_none())
}

fn network_private_missing_membership_cert(config: &Config) -> bool {
    is_private(config)
        && config
            .network
            .as_ref()
            .is_some_and(|n| n.membership_cert.is_none())
}

fn network_id_wrong_format(config: &Config) -> bool {
    let Some(nid) = config.network.as_ref().and_then(|n| n.network_id.as_ref()) else {
        return false;
    };
    nid.len() != 64
        || !nid
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}
