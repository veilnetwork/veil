//! Per-target routing policy for oproxy-client.
//!
//! Resolves each `(host, port)` to a concrete [`ProxyMode`] using the
//! `[routing]` section of `ClientConfig`:
//!
//! 1. Walk `rules` in order; first match wins.
//! 2. If no rule matches, use `default`.
//!
//! `host` is matched against `host_suffix` / `host_exact` (case-
//! insensitive).  If `host` parses as an IP literal, it's also matched
//! against `cidr`.  Port range matches against `port_range`.
//!
//! Direct connect and fallback semantics are implemented in the inbound
//! handlers via [`open_direct_and_bridge`].
//!
//! Audit batch 2026-05-23.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow};
use tokio::io::copy;
use tokio::net::TcpStream;

use crate::config::{FallbackMode, ProxyMode, RoutingConfig, RoutingRule};

/// Effective routing decision for a single `(host, port)`: which mode
/// to use AND which fallback to apply if veil fails.  The fallback
/// component is meaningful only when `mode = Veil`; for `Direct` /
/// `Block` it's ignored (but still carried so callers don't have to
/// special-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub mode: ProxyMode,
    pub fallback: FallbackMode,
}

/// Resolve a `(host, port)` to the routing decision chosen by the
/// configured policy.  Per-rule `fallback` overrides the global
/// `[routing] fallback`; unmatched-default uses the global.
pub fn resolve(cfg: &RoutingConfig, host: &str, port: u16) -> Decision {
    for rule in &cfg.rules {
        if rule_matches(rule, host, port) {
            return Decision {
                mode: rule.action,
                fallback: rule.fallback.unwrap_or(cfg.fallback),
            };
        }
    }
    Decision {
        mode: cfg.default,
        fallback: cfg.fallback,
    }
}

fn rule_matches(rule: &RoutingRule, host: &str, port: u16) -> bool {
    // A rule is a conjunction: every supplied field must match.  Empty
    // fields are wildcards.  If ALL fields are empty, the rule matches
    // everything (intentional: lets operators flip the default via a
    // single all-wildcard rule).
    let host_lower = host.to_ascii_lowercase();

    if let Some(suffix) = &rule.host_suffix
        && !host_lower.ends_with(&suffix.to_ascii_lowercase())
    {
        return false;
    }
    if let Some(exact) = &rule.host_exact
        && host_lower != exact.to_ascii_lowercase()
    {
        return false;
    }
    if let Some(cidr) = &rule.cidr {
        if let Ok(parsed) = host.parse::<IpAddr>() {
            if !cidr_contains(cidr, parsed) {
                return false;
            }
        } else {
            // Not IP literal → cidr can't match.  Reject (rule does not
            // apply to hostname targets).
            return false;
        }
    }
    if let Some(range) = &rule.port_range
        && !port_in_range(range, port)
    {
        return false;
    }
    true
}

fn cidr_contains(cidr_str: &str, ip: IpAddr) -> bool {
    let Some((net, prefix_str)) = cidr_str.split_once('/') else {
        // No prefix → treat as /32 (v4) or /128 (v6).
        return cidr_str.parse::<IpAddr>().is_ok_and(|n| n == ip);
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match (net.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(net4)), IpAddr::V4(ip4)) if prefix <= 32 => {
            ipv4_in_subnet(net4, prefix, ip4)
        }
        (Ok(IpAddr::V6(net6)), IpAddr::V6(ip6)) if prefix <= 128 => {
            ipv6_in_subnet(net6, prefix, ip6)
        }
        _ => false,
    }
}

fn ipv4_in_subnet(net: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX.wrapping_shl((32 - prefix) as u32);
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn ipv6_in_subnet(net: Ipv6Addr, prefix: u8, ip: Ipv6Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = u128::MAX.wrapping_shl((128 - prefix) as u32);
    (u128::from(net) & mask) == (u128::from(ip) & mask)
}

fn port_in_range(range: &str, port: u16) -> bool {
    if let Some((lo_str, hi_str)) = range.split_once('-') {
        let Ok(lo) = lo_str.trim().parse::<u16>() else {
            return false;
        };
        let Ok(hi) = hi_str.trim().parse::<u16>() else {
            return false;
        };
        port >= lo && port <= hi
    } else {
        range
            .trim()
            .parse::<u16>()
            .map(|p| p == port)
            .unwrap_or(false)
    }
}

/// Reject loopback / private / multicast / link-local / cloud-metadata
/// destinations. audit cycle-6 (A9): kept in the lib (not just the server bin)
/// so the client `Direct` path can apply the same SSRF guard. Canonicalises
/// IPv4-mapped IPv6 (`::ffff:x.x.x.x`) first — its leading segment is 0x0000 so
/// it bypassed the V6 prefix checks AND `is_loopback()` (the CRITICAL SSRF fix
/// from audit 2026-05-29). Keep in sync with `veil-proxy::exit::
/// is_forbidden_destination` and the oproxy server bin's copy.
pub fn is_forbidden_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    // Canonicalise IPv4-mapped (`::ffff:x.x.x.x`) AND the deprecated
    // IPv4-compatible (`::x.x.x.x`, RFC 4291 §2.5.5.1) IPv6 forms to V4 before
    // classification — both embed a V4 address whose leading V6 segment is
    // 0x0000, bypassing the V6 prefix checks and `is_loopback()` (audit cycle-6
    // hardened the IPv4-compatible case on top of the audit-2026-05-29
    // IPv4-mapped fix).
    let ip = match ip {
        IpAddr::V6(v6) => {
            let c = v6.to_canonical(); // handles ::ffff:x.x.x.x
            if c.is_ipv4() {
                c
            } else {
                let s = v6.segments();
                // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): the embedded
                // V4 lives in the low 32 bits, but its leading segment is 0x0064
                // (non-zero) so `to_canonical()` leaves it as V6 and it dodges
                // the fc00::/fe80:: prefix checks below. Translate + re-classify
                // so 64:ff9b::169.254.169.254 / ::10.0.0.1 stay forbidden.
                let is_nat64 = s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|&x| x == 0);
                // IPv4-compatible: first 96 bits zero, low 32 bits the V4 addr
                // (exclude `::` unspecified and `::1` loopback, already caught).
                if is_nat64 || (s[0..6].iter().all(|&x| x == 0) && (s[6] != 0 || s[7] > 1)) {
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        (s[6] >> 8) as u8,
                        (s[6] & 0xff) as u8,
                        (s[7] >> 8) as u8,
                        (s[7] & 0xff) as u8,
                    ))
                } else {
                    IpAddr::V6(v6)
                }
            }
        }
        other => other,
    };
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            // RFC 6598 Shared Address Space / CGNAT 100.64.0.0/10 — internal
            // carrier infra, must be treated like RFC1918.
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0xC0) == 64;
            // 0.0.0.0/8 ("this network", RFC 1122) — only 0.0.0.0 itself is
            // caught by is_unspecified() above; reject the whole /8.
            o[0] == 0 || v4.is_private() || v4.is_link_local() || v4.is_broadcast() || is_cgnat
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            let is_unique_local = (seg & 0xFE00) == 0xFC00;
            let is_link_local = (seg & 0xFFC0) == 0xFE80;
            is_unique_local || is_link_local
        }
    }
}

/// Resolve `target` (`host:port`), apply the SSRF filter unless `allow_private`,
/// and return a connected, timeout-bounded [`TcpStream`] to a vetted address.
///
/// audit cycle-6 (A9 + review): shared by EVERY direct-egress path (CONNECT and
/// plain-HTTP-prelude). Rejects the WHOLE connection if ANY resolved address is
/// forbidden (deny-if-any — matches the server-side policy and closes
/// split-horizon DNS where a public answer fronts a private one), then dials the
/// chosen address BY IP (not the host string) so a re-resolution can't slip a
/// forbidden IP past the check (DNS-rebinding TOCTOU).
pub(crate) async fn connect_direct_vetted(target: &str, allow_private: bool) -> Result<TcpStream> {
    let connect_addr: Option<std::net::SocketAddr> = if allow_private {
        None // legacy behaviour: let TcpStream::connect resolve+dial the host
    } else {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(target)
            .await
            .with_context(|| format!("direct TCP resolve of {target} failed"))?
            .collect();
        if addrs.is_empty() {
            return Err(anyhow!(
                "direct TCP to {target}: host resolved to no addresses"
            ));
        }
        if let Some(bad) = addrs.iter().find(|sa| is_forbidden_ip(sa.ip())) {
            return Err(anyhow!(
                "direct TCP to {target} refused: resolves to forbidden address {} \
                 (set [routing] allow_private = true to permit)",
                bad.ip()
            ));
        }
        Some(addrs[0])
    };

    // Audit batch 2026-05-24: bound on a blackhole target.  Without this,
    // a dst routed to a silent IP holds the task for the OS default
    // connect-retry budget (~2-3 min on Linux).
    let connect_fut = async {
        match connect_addr {
            Some(sa) => TcpStream::connect(sa).await,
            None => TcpStream::connect(target).await,
        }
    };
    tokio::time::timeout(crate::timeouts::DIRECT_CONNECT_TIMEOUT, connect_fut)
        .await
        .map_err(|_| {
            anyhow!(
                "direct TCP connect to {target} timed out ({:?})",
                crate::timeouts::DIRECT_CONNECT_TIMEOUT
            )
        })?
        .with_context(|| format!("direct TCP connect to {target} failed"))
}

/// Open a direct outbound TCP socket to `host:port` and bridge it
/// bidirectionally with the inbound stream.  Used by both the
/// `Direct` proxy mode and the `Fallback::Direct` recovery path.
/// SSRF-filtered via [`connect_direct_vetted`] unless `allow_private`.
pub async fn open_direct_and_bridge(
    inbound: TcpStream,
    host: String,
    port: u16,
    allow_private: bool,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let target = format!("{host}:{port}");
    let outbound = connect_direct_vetted(&target, allow_private).await?;
    log::debug!("oproxy.routing.direct: bridged {target}");

    let (mut in_r, mut in_w) = inbound.into_split();
    let (mut out_r, mut out_w) = outbound.into_split();
    let up = async {
        let _ = copy(&mut in_r, &mut out_w).await;
        let _ = out_w.shutdown().await;
    };
    let down = async {
        let _ = copy(&mut out_r, &mut in_w).await;
        let _ = in_w.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

/// Resolve mode and dispatch — used by inbound handlers.  Returns
/// `Ok(true)` if the connection was handled (either successfully or with
/// a graceful close); `Ok(false)` if the policy was `Block`; `Err`
/// for unexpected I/O failure.
///
/// `try_veil` — closure that attempts the veil path; returns
/// `Err` if veil leg failed (server unreachable / timeout / etc.).
/// Caller passes a small async fn that closes over the AppHandle and
/// `(host, port)`.
pub async fn dispatch<F, Fut>(
    cfg: &RoutingConfig,
    inbound: TcpStream,
    host: String,
    port: u16,
    try_veil: F,
) -> Result<bool>
where
    F: FnOnce(TcpStream, String, u16) -> Fut,
    Fut: std::future::Future<Output = Result<(), (TcpStream, anyhow::Error)>>,
{
    let decision = resolve(cfg, &host, port);
    log::debug!("oproxy.routing: {host}:{port} → {decision:?}");
    match decision.mode {
        ProxyMode::Block => {
            log::info!("oproxy.routing: BLOCK {host}:{port}");
            // Close inbound by dropping; caller's handler can write
            // protocol-specific reject reply before calling dispatch.
            Ok(false)
        }
        ProxyMode::Direct => {
            open_direct_and_bridge(inbound, host, port, cfg.allow_private).await?;
            Ok(true)
        }
        ProxyMode::Veil => match try_veil(inbound, host.clone(), port).await {
            Ok(()) => Ok(true),
            Err((inbound, err)) => match decision.fallback {
                crate::config::FallbackMode::Fail => {
                    Err(anyhow!("veil failed (no fallback): {err}"))
                }
                crate::config::FallbackMode::Direct => {
                    log::warn!(
                        "oproxy.routing: veil failed for {host}:{port}, falling back direct: {err}"
                    );
                    open_direct_and_bridge(inbound, host, port, cfg.allow_private).await?;
                    Ok(true)
                }
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FallbackMode, ProxyMode, RoutingConfig, RoutingRule};

    fn rule_suffix(s: &str, action: ProxyMode) -> RoutingRule {
        RoutingRule {
            host_suffix: Some(s.into()),
            host_exact: None,
            cidr: None,
            port_range: None,
            action,
            fallback: None,
        }
    }

    fn rule_cidr(c: &str, action: ProxyMode) -> RoutingRule {
        RoutingRule {
            host_suffix: None,
            host_exact: None,
            cidr: Some(c.into()),
            port_range: None,
            action,
            fallback: None,
        }
    }

    fn rule_cidr_with_fallback(
        c: &str,
        action: ProxyMode,
        fallback: Option<FallbackMode>,
    ) -> RoutingRule {
        RoutingRule {
            host_suffix: None,
            host_exact: None,
            cidr: Some(c.into()),
            port_range: None,
            action,
            fallback,
        }
    }

    // Shorthand for existing tests that only check the resolved mode.
    fn resolve_mode(cfg: &RoutingConfig, host: &str, port: u16) -> ProxyMode {
        resolve(cfg, host, port).mode
    }

    #[test]
    fn no_rules_uses_default() {
        let cfg = RoutingConfig {
            default: ProxyMode::Direct,
            fallback: FallbackMode::Fail,
            rules: vec![],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "example.com", 443), ProxyMode::Direct);
    }

    /// audit cycle-6 (A9): is_forbidden_ip blocks the SSRF-sensitive ranges
    /// (incl. the IPv4-mapped-IPv6 bypass) and admits public addresses.
    #[test]
    fn is_forbidden_ip_blocks_private_and_mapped() {
        use std::net::IpAddr;
        let blocked = [
            "127.0.0.1",                // loopback v4
            "10.1.2.3",                 // RFC1918
            "192.168.0.1",              // RFC1918
            "172.16.5.5",               // RFC1918
            "169.254.169.254",          // cloud metadata / link-local
            "100.64.0.1",               // CGNAT (RFC 6598)
            "100.127.255.254",          // CGNAT upper edge
            "::1",                      // loopback v6
            "fd00::1",                  // ULA
            "fe80::1",                  // link-local v6
            "::ffff:127.0.0.1",         // IPv4-mapped loopback (the bypass)
            "::ffff:169.254.169.254",   // IPv4-mapped metadata (the bypass)
            "::ffff:100.64.0.1",        // IPv4-mapped CGNAT
            "::127.0.0.1",              // IPv4-COMPATIBLE loopback (deprecated bypass)
            "::169.254.169.254",        // IPv4-compatible metadata
            "0.0.0.0",                  // unspecified
            "0.0.0.1",                  // 0.0.0.0/8 ("this network", RFC 1122)
            "0.255.255.255",            // 0.0.0.0/8 upper edge
            "64:ff9b::169.254.169.254", // NAT64 (RFC 6052) embedding metadata
            "64:ff9b::10.0.0.1",        // NAT64 embedding RFC1918
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_forbidden_ip(ip), "{s} must be forbidden");
        }
        let allowed = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "100.63.255.255",   // just below CGNAT 100.64/10
            "100.128.0.1",      // just above CGNAT
            "1.0.0.1",          // just above 0.0.0.0/8
            "64:ff9b::8.8.8.8", // NAT64 embedding a PUBLIC V4 (no over-block)
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_forbidden_ip(ip), "{s} must be allowed");
        }
    }

    #[test]
    fn host_suffix_matches_case_insensitively() {
        let cfg = RoutingConfig {
            default: ProxyMode::Veil,
            fallback: FallbackMode::Fail,
            rules: vec![rule_suffix(".internal", ProxyMode::Direct)],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "db.internal", 5432), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "DB.INTERNAL", 5432), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "app.db.internal", 80), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "external.com", 443), ProxyMode::Veil);
    }

    #[test]
    fn cidr_matches_ipv4_literals_only() {
        let cfg = RoutingConfig {
            default: ProxyMode::Veil,
            fallback: FallbackMode::Fail,
            rules: vec![rule_cidr("10.0.0.0/8", ProxyMode::Direct)],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "10.0.0.5", 22), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "10.255.255.255", 22), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "172.16.0.1", 22), ProxyMode::Veil);
        // Hostname (not IP literal) does NOT match a cidr rule.
        assert_eq!(resolve_mode(&cfg, "10.example.com", 22), ProxyMode::Veil);
    }

    #[test]
    fn cidr_matches_ipv6() {
        let cfg = RoutingConfig {
            default: ProxyMode::Veil,
            fallback: FallbackMode::Fail,
            rules: vec![rule_cidr("fd00::/8", ProxyMode::Direct)],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "fd00::1", 22), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "fe80::1", 22), ProxyMode::Veil);
    }

    #[test]
    fn port_range_inclusive_bounds() {
        let r = RoutingRule {
            host_suffix: None,
            host_exact: None,
            cidr: None,
            port_range: Some("1024-65535".into()),
            action: ProxyMode::Direct,
            fallback: None,
        };
        let cfg = RoutingConfig {
            default: ProxyMode::Veil,
            fallback: FallbackMode::Fail,
            rules: vec![r],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "x", 22), ProxyMode::Veil);
        assert_eq!(resolve_mode(&cfg, "x", 1024), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "x", 65535), ProxyMode::Direct);
    }

    #[test]
    fn port_range_single_port() {
        let r = RoutingRule {
            host_suffix: None,
            host_exact: None,
            cidr: None,
            port_range: Some("443".into()),
            action: ProxyMode::Veil,
            fallback: None,
        };
        let cfg = RoutingConfig {
            default: ProxyMode::Direct,
            fallback: FallbackMode::Fail,
            rules: vec![r],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "x", 80), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "x", 443), ProxyMode::Veil);
    }

    #[test]
    fn rules_evaluated_in_order_first_match_wins() {
        let cfg = RoutingConfig {
            default: ProxyMode::Block,
            fallback: FallbackMode::Fail,
            rules: vec![
                rule_suffix(".internal", ProxyMode::Direct),
                rule_suffix(".com", ProxyMode::Veil),
            ],
            allow_private: false,
        };
        // "x.internal" — only first rule (.internal suffix) matches.
        assert_eq!(resolve_mode(&cfg, "x.internal", 1), ProxyMode::Direct);
        // "x.com" — first rule does not match, second wins.
        assert_eq!(resolve_mode(&cfg, "x.com", 1), ProxyMode::Veil);
        // "x.org" — no rule matches → default.
        assert_eq!(resolve_mode(&cfg, "x.org", 1), ProxyMode::Block);
    }

    #[test]
    fn host_suffix_with_double_match_takes_first_rule() {
        // Rules overlap: ".dev.internal" comes before ".internal".
        let cfg = RoutingConfig {
            default: ProxyMode::Veil,
            fallback: FallbackMode::Fail,
            rules: vec![
                rule_suffix(".dev.internal", ProxyMode::Block),
                rule_suffix(".internal", ProxyMode::Direct),
            ],
            allow_private: false,
        };
        // "app.dev.internal" matches both, but first rule wins.
        assert_eq!(resolve_mode(&cfg, "app.dev.internal", 1), ProxyMode::Block);
        // "db.internal" matches only second rule.
        assert_eq!(resolve_mode(&cfg, "db.internal", 1), ProxyMode::Direct);
    }

    #[test]
    fn conjunction_of_fields_in_single_rule() {
        // Rule: tcp to 192.168.0.0/16 on port 22 only → Direct.
        let r = RoutingRule {
            host_suffix: None,
            host_exact: None,
            cidr: Some("192.168.0.0/16".into()),
            port_range: Some("22".into()),
            action: ProxyMode::Direct,
            fallback: None,
        };
        let cfg = RoutingConfig {
            default: ProxyMode::Veil,
            fallback: FallbackMode::Fail,
            rules: vec![r],
            allow_private: false,
        };
        assert_eq!(resolve_mode(&cfg, "192.168.1.1", 22), ProxyMode::Direct);
        assert_eq!(resolve_mode(&cfg, "192.168.1.1", 443), ProxyMode::Veil); // wrong port
        assert_eq!(resolve_mode(&cfg, "10.0.0.1", 22), ProxyMode::Veil); // wrong cidr
    }

    // ── Per-rule fallback ─────────────────────────────────────────────

    #[test]
    fn per_rule_fallback_overrides_global() {
        let cfg = RoutingConfig {
            default: ProxyMode::Direct,
            fallback: FallbackMode::Direct, // global default
            rules: vec![
                // 10.0.0.0/8 — veil with fallback to direct (inherits global)
                rule_cidr_with_fallback("10.0.0.0/8", ProxyMode::Veil, None),
                // 172.16.0.0/12 — veil with per-rule "fail" override
                rule_cidr_with_fallback("172.16.0.0/12", ProxyMode::Veil, Some(FallbackMode::Fail)),
            ],
            allow_private: false,
        };

        let d10 = resolve(&cfg, "10.5.5.5", 80);
        assert_eq!(d10.mode, ProxyMode::Veil);
        assert_eq!(d10.fallback, FallbackMode::Direct); // inherited global

        let d172 = resolve(&cfg, "172.16.5.5", 80);
        assert_eq!(d172.mode, ProxyMode::Veil);
        assert_eq!(d172.fallback, FallbackMode::Fail); // per-rule override
    }

    /// Documents the user-asked scenario from audit batch 2026-05-24:
    /// * 10.0.0.0/8  → veil, fallback to direct
    /// * 172.16.0.0/12 → veil, no fallback
    /// * 192.168.0.0/16 → direct (never veil)
    #[test]
    fn user_scenario_rfc1918_split() {
        let cfg = RoutingConfig {
            default: ProxyMode::Veil, // everything else: veil (default)
            fallback: FallbackMode::Fail,
            rules: vec![
                rule_cidr_with_fallback("10.0.0.0/8", ProxyMode::Veil, Some(FallbackMode::Direct)),
                rule_cidr_with_fallback("172.16.0.0/12", ProxyMode::Veil, Some(FallbackMode::Fail)),
                rule_cidr_with_fallback("192.168.0.0/16", ProxyMode::Direct, None),
            ],
            allow_private: false,
        };

        // 10.x.x.x — veil, fall back to direct on failure
        let d = resolve(&cfg, "10.42.1.1", 5432);
        assert_eq!(d.mode, ProxyMode::Veil);
        assert_eq!(d.fallback, FallbackMode::Direct);

        // 172.16-31.x — veil, NO fallback
        let d = resolve(&cfg, "172.20.0.1", 5432);
        assert_eq!(d.mode, ProxyMode::Veil);
        assert_eq!(d.fallback, FallbackMode::Fail);

        // 172.32.x — does NOT match /12 (12.0..31.255 only), falls through to default
        let d = resolve(&cfg, "172.32.0.1", 5432);
        assert_eq!(d.mode, ProxyMode::Veil); // default
        assert_eq!(d.fallback, FallbackMode::Fail); // global

        // 192.168.x — direct, never veil
        let d = resolve(&cfg, "192.168.1.1", 5432);
        assert_eq!(d.mode, ProxyMode::Direct);

        // anything else — default veil
        let d = resolve(&cfg, "8.8.8.8", 53);
        assert_eq!(d.mode, ProxyMode::Veil);
        assert_eq!(d.fallback, FallbackMode::Fail);
    }
}
