//! Bridge [`Config`] [`veil_transport::TransportContext`].
//!
//! `TransportContext::from_config` previously lived in
//! `veil_transport::context` but it pulled in the cfg layer, which broke
//! the desired Tier-2 layering (transport doesn't know about cfg). The body
//! is preserved verbatim here on the cfg side; transport only exposes the
//! primitive builders (`with_tcp_connect_timeout`, `with_default_sni`
//! `with_trusted_certificates`, `with_system_roots`) that this glue calls.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use veil_transport::fingerprint::{TlsFingerprint, TlsFingerprintPolicy};
use veil_transport::{Result, TlsContext, TransportContext, TransportError};

use super::{Config, TlsFingerprintConfig};

/// Translate the `[transport.tls_fingerprint]` config into the runtime
/// [`TlsFingerprintPolicy`]. Returns a clear config error on an unknown mode
/// or profile token (mirrors the obfs4-variant parsing convention).
fn build_fingerprint_policy(cfg: &TlsFingerprintConfig) -> Result<TlsFingerprintPolicy> {
    let parse = |tok: &str| -> Result<TlsFingerprint> {
        TlsFingerprint::parse(tok).ok_or_else(|| {
            TransportError::Unsupported(format!(
                "[transport.tls_fingerprint] unknown profile {tok:?} \
                 (accept: chrome|firefox|safari|ios|android|random)"
            ))
        })
    };
    let policy = match cfg.mode.trim().to_ascii_lowercase().as_str() {
        "pinned" => TlsFingerprintPolicy::pinned(parse(&cfg.profile)?),
        "rotate" => {
            let mut order = Vec::with_capacity(cfg.rotation.len());
            for tok in &cfg.rotation {
                order.push(parse(tok)?);
            }
            TlsFingerprintPolicy::rotate(order, cfg.sticky)
        }
        "random" => TlsFingerprintPolicy::random(),
        other => {
            return Err(TransportError::Unsupported(format!(
                "[transport.tls_fingerprint] unknown mode {other:?} \
                 (accept: pinned|rotate|random)"
            )));
        }
    };
    Ok(policy)
}

/// Build a [`TransportContext`] from `[transport]`-section knobs in `Config`.
///
/// no browser-impersonation validation left — every removed field
/// has been deleted from the config schema, so the load is pure assemble.
pub fn context_from_config(config: &Config) -> Result<TransportContext> {
    let connect_timeout = Duration::from_millis(
        config
            .transport
            .tls_client
            .connect_timeout_ms
            .unwrap_or(3_000),
    );

    // TLS ClientHello fingerprint policy ([transport.tls_fingerprint]).
    // Parsed up-front so an unknown mode/profile token fails the config load
    // with a clear error rather than silently falling back.
    let fingerprint_policy = build_fingerprint_policy(&config.transport.tls_fingerprint)?;

    let mut ctx = TransportContext::for_debug()?
        .with_tcp_connect_timeout(connect_timeout)
        .with_default_sni(config.transport.default_sni.clone())
        // Этап 10 slice 2b — propagate the GREASE ECH опт-in flag
        // от `[global] tls_ech_grease` к the transport layer.  Default
        // remains `false` (foundation flag); slice 2c flips к `true`.
        .with_tls_ech_grease(config.global.tls_ech_grease)
        // Runtime TLS fingerprint rotation policy (tls-boring path).
        .with_tls_fingerprint(fingerprint_policy);

    // apply TLS trust-store config knobs.
    // closed the build-flag footgun — `use_system_roots = true`
    // is now respected unconditionally (webpki-roots is а direct dep
    // either way). The `tls-webpki-roots` feature is now а no-op kept
    // for existing build configs; scheduled for removal в semver-major.
    let tls_cfg = &config.transport.tls_client;
    if tls_cfg.use_system_roots {
        ctx.tls = ctx.tls.with_system_roots(true)?;
    }
    if let Some(ref ca_path) = tls_cfg.trusted_ca_file {
        let certs = TlsContext::load_certificates_from_file(ca_path)
            .map_err(|err| TransportError::Tls(err.to_string()))?;
        ctx.tls = ctx.tls.with_trusted_certificates(certs)?;
    }

    // Load obfs4 PSK from file if configured.  File format: one line of
    // base64-encoded 32-byte key.  Trailing whitespace stripped.
    if let Some(ref psk_path) = config.transport.obfs4_psk_file {
        let raw = std::fs::read_to_string(psk_path).map_err(|e| {
            TransportError::Unsupported(format!("obfs4_psk_file: read {}: {e}", psk_path.display()))
        })?;
        let trimmed = raw.trim();
        let decoded = BASE64.decode(trimmed).map_err(|e| {
            TransportError::Unsupported(format!(
                "obfs4_psk_file: invalid base64 в {}: {e}",
                psk_path.display()
            ))
        })?;
        if decoded.len() != 32 {
            return Err(TransportError::Unsupported(format!(
                "obfs4_psk_file: expected 32 bytes, got {} в {}",
                decoded.len(),
                psk_path.display()
            )));
        }
        let mut psk = [0u8; 32];
        psk.copy_from_slice(&decoded);
        ctx.obfs4_psk = Some(Arc::new(psk));
    }

    // Webtunnel config wiring.
    if let Some(ref path) = config.transport.webtunnel_secret_path {
        ctx.webtunnel_secret_path = Some(path.clone());
    }
    if let Some(ref token_path) = config.transport.webtunnel_auth_token_file {
        // Token is stored AS-IS — каждый wire-byte op (sending в header,
        // comparing на receive) treats it як opaque bytes.  Operators
        // typically use base64 ASCII so the file is greppable, но any
        // printable-ASCII secret works.  Trailing whitespace/newline
        // trimmed; otherwise file content == token verbatim.
        let raw = std::fs::read_to_string(token_path).map_err(|e| {
            TransportError::Unsupported(format!(
                "webtunnel_auth_token_file: read {}: {e}",
                token_path.display()
            ))
        })?;
        let token = raw.trim().as_bytes().to_vec();
        ctx.webtunnel_auth_token = Some(Arc::new(token));
    }
    if let Some(ref dir) = config.transport.webtunnel_decoy_dir {
        ctx.webtunnel_decoy_dir = Some(dir.clone());
    }
    // Anti-censorship: optional SOCKS fallback for outbound dials.
    // Default `None` — direct outbound only.  Operator opts in by
    // setting `[transport] outbound_socks_fallback_proxy = "socks5://..."`.
    if let Some(ref proxy) = config.transport.outbound_socks_fallback_proxy {
        ctx.outbound_socks_fallback_proxy = Some(proxy.clone());
    }
    // Phase 2 kill-switch: parse operator-config variant lists into
    // typed `WireFormatVariant` collections.  Empty config → V1 default
    // (matches pre-Phase-2 behavior bit-for-bit).
    if !config.transport.obfs4_accept_variants.is_empty() {
        let mut variants = Vec::with_capacity(config.transport.obfs4_accept_variants.len());
        for raw in &config.transport.obfs4_accept_variants {
            let v = veil_transport::WireFormatVariant::from_config_str(raw).ok_or_else(|| {
                TransportError::Unsupported(format!(
                    "obfs4_accept_variants: unknown variant {raw:?} (accept: \"v1\", \"v2\")"
                ))
            })?;
            variants.push(v);
        }
        ctx.obfs4_accept_variants = variants;
    }
    if let Some(raw) = &config.transport.obfs4_client_variant {
        ctx.obfs4_client_variant = veil_transport::WireFormatVariant::from_config_str(raw)
            .ok_or_else(|| {
                TransportError::Unsupported(format!(
                    "obfs4_client_variant: unknown variant {raw:?} (accept: \"v1\", \"v2\")"
                ))
            })?;
    }
    // Anti-censorship P2 #7: bandwidth mimicry — design landing-pad
    // recognised here so operators can pre-bake the flag, но не
    // wired yet (см. docs/internal/PLAN_BANDWIDTH_MIMICRY.md).  Fail-closed
    // gate (audit batch 2026-05-23): if the operator sets the flag
    // without also acknowledging the no-op via `experimental_allow_noop_mimicry`,
    // refuse to start.  Pre-fix the daemon only WARN-logged и kept
    // running, which gave operators а false sense of DPI resistance.
    if config.transport.bandwidth_mimicry_enabled {
        if !config.transport.experimental_allow_noop_mimicry {
            return Err(TransportError::Unsupported(
                "[transport] bandwidth_mimicry_enabled = true but the feature \
                 wire-up is deferred (см. docs/internal/PLAN_BANDWIDTH_MIMICRY.md). \
                 Setting it on its own gives а false sense of DPI resistance \
                 because nothing actually shapes the traffic.  Either set it \
                 back к false, OR also set experimental_allow_noop_mimicry = \
                 true к explicitly acknowledge the daemon will run без \
                 mimicry.  Use operator-side tc/qdisc (см. \
                 docs/internal/DEPLOYMENT_HARDENING.md) if you need throughput-\
                 shape resistance now."
                    .to_string(),
            ));
        }
        log::warn!(
            target: "config.transport",
            "bandwidth_mimicry_enabled=true (experimental_allow_noop_mimicry=true): \
             feature wire-up is deferred — setting recognised but no-op. \
             See docs/internal/PLAN_BANDWIDTH_MIMICRY.md."
        );
        if let Some(ref profile) = config.transport.bandwidth_mimicry_profile {
            log::info!(
                target: "config.transport",
                "bandwidth_mimicry_profile={profile} (recorded but no-op)"
            );
        }
    }
    Ok(ctx)
}

#[cfg(test)]
mod bandwidth_mimicry_failclosed_tests {
    use super::*;
    use crate::Config;

    #[test]
    fn enabled_alone_fails_validation() {
        let mut cfg = Config::default();
        cfg.transport.bandwidth_mimicry_enabled = true;
        // experimental_allow_noop_mimicry left at its default `false`.
        let err = context_from_config(&cfg).expect_err(
            "enabling mimicry without ack must fail — regression bar для audit batch 2026-05-23",
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("bandwidth_mimicry_enabled")
                || msg.contains("experimental_allow_noop_mimicry"),
            "diagnostic must name the relevant config keys, got: {msg}"
        );
    }

    #[test]
    fn enabled_with_ack_starts_with_warn() {
        let mut cfg = Config::default();
        cfg.transport.bandwidth_mimicry_enabled = true;
        cfg.transport.experimental_allow_noop_mimicry = true;
        // Should succeed (operator explicitly acknowledged the no-op).
        let _ = context_from_config(&cfg).expect("ack flag pairs with enabled — daemon must start");
    }

    #[test]
    fn disabled_default_compiles_clean() {
        // The common path — neither flag set — must keep working unchanged.
        let cfg = Config::default();
        assert!(!cfg.transport.bandwidth_mimicry_enabled);
        assert!(!cfg.transport.experimental_allow_noop_mimicry);
        let _ = context_from_config(&cfg).expect("default config must build");
    }
}

#[cfg(test)]
mod tls_fingerprint_config_tests {
    use super::*;
    use veil_transport::fingerprint::{TlsFingerprint, TlsFingerprintMode};

    fn cfg(mode: &str, profile: &str, rotation: &[&str], sticky: bool) -> TlsFingerprintConfig {
        TlsFingerprintConfig {
            mode: mode.to_owned(),
            profile: profile.to_owned(),
            rotation: rotation.iter().map(|s| (*s).to_owned()).collect(),
            sticky,
        }
    }

    #[test]
    fn default_config_builds_sticky_desktop_rotation() {
        let pol = build_fingerprint_policy(&TlsFingerprintConfig::default()).unwrap();
        match pol.mode() {
            TlsFingerprintMode::Rotate(list) => assert_eq!(
                list,
                &[
                    TlsFingerprint::Chrome,
                    TlsFingerprint::Firefox,
                    TlsFingerprint::Safari
                ]
            ),
            other => panic!("expected rotate, got {other:?}"),
        }
        assert!(pol.is_sticky());
    }

    #[test]
    fn pinned_and_random_modes_parse() {
        assert_eq!(
            build_fingerprint_policy(&cfg("pinned", "firefox", &[], false))
                .unwrap()
                .mode(),
            &TlsFingerprintMode::Pinned(TlsFingerprint::Firefox)
        );
        assert_eq!(
            build_fingerprint_policy(&cfg("random", "chrome", &[], false))
                .unwrap()
                .mode(),
            &TlsFingerprintMode::Random
        );
    }

    #[test]
    fn rotate_list_parses_mobile_profiles() {
        let pol = build_fingerprint_policy(&cfg(
            "rotate",
            "chrome",
            &["ios", "android", "safari"],
            true,
        ))
        .unwrap();
        match pol.mode() {
            TlsFingerprintMode::Rotate(list) => assert_eq!(
                list,
                &[
                    TlsFingerprint::IosSafari,
                    TlsFingerprint::AndroidChrome,
                    TlsFingerprint::Safari
                ]
            ),
            other => panic!("expected rotate, got {other:?}"),
        }
    }

    #[test]
    fn unknown_mode_and_profile_are_config_errors() {
        let e1 = build_fingerprint_policy(&cfg("bogus", "chrome", &[], false)).unwrap_err();
        assert!(format!("{e1}").contains("unknown mode"), "{e1}");
        let e2 = build_fingerprint_policy(&cfg("pinned", "netscape", &[], false)).unwrap_err();
        assert!(format!("{e2}").contains("unknown profile"), "{e2}");
    }

    #[test]
    fn full_context_load_respects_fingerprint_config() {
        let mut c = Config::default();
        c.transport.tls_fingerprint = cfg("pinned", "safari", &[], false);
        let ctx = context_from_config(&c).expect("valid fingerprint config must load");
        assert_eq!(
            ctx.tls_fingerprint.mode(),
            &TlsFingerprintMode::Pinned(TlsFingerprint::Safari)
        );
    }
}
