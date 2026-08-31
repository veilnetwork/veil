//! Small URI and config-decoding helpers shared by the runtime hot path.
//!
//! All functions here are pure (no I/O, no locks) and stateless.  They
//! exist as a single home for low-level string / config parsing that
//! was previously sprinkled through the tail of runtime/mod.rs.

use base64::Engine as _;

use veil_cfg::{self, Config};
use veil_proto::budget::{LABEL_WIDTH, MAX_TARGET_LABELS};
use veil_proto::control::NatCandidate;
use veil_transport::TransportUri;

/// Rewrite a `TransportUri` template by substituting the `NatCandidate`'s
/// IP+port for the template's host+port.  Returns `None` for malformed
/// candidates (wrong addr length for the declared `atyp`), unknown `atyp`
/// values, or template variants where NAT promotion is not meaningful
/// (Unix / Socks / Ws — see `TransportUri::with_host_port`).
///
/// IPv6 hosts are wrapped in brackets so that the resulting URI parses
/// correctly when round-tripped through `TransportUri::parse` (`url::Url`
/// rejects bare colons in the host component).
pub fn nat_candidate_to_transport_uri(
    c: &NatCandidate,
    template: &TransportUri,
) -> Option<TransportUri> {
    use std::net::IpAddr;
    let socket = veil_nat::candidate_to_socket_addr(c)?;
    let host = match socket.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    template.with_host_port(host, socket.port())
}

/// True when `uri` carries the placeholder `:0` port that operators use in
/// sim configs to request "pick any free port".  Production deploys
/// typically use explicit ports or `advertise` overrides.
///
/// Avoids a full URI parse on the per-handshake hot path.  Accepts both
/// `tcp://host:0` and `tcp://[::]:0` — both end in the literal `:0` suffix.
pub fn uri_has_port_zero(uri: &str) -> bool {
    uri.ends_with(":0")
}

/// Extract the scheme prefix from a URI (`tcp://...` → `Some("tcp")`).
/// Returns `None` for malformed URIs without a `://` separator.
pub fn uri_scheme(uri: &str) -> Option<&str> {
    uri.split_once("://").map(|(scheme, _)| scheme)
}

/// True when `uri` parses as `tcp://<host>:<port>` and `<host>` is the
/// IPv4 / IPv6 wildcard (`0.0.0.0` or `::`).  Used to drop these entries
/// from the PEX advertise set since they're never reachable from peers.
pub fn is_wildcard_transport(uri: &str) -> bool {
    // Accept either "tcp://0.0.0.0:..." / "tcp://[::]:..." plus tls/ws
    // variants by checking the substring after the scheme separator.
    // Anything that doesn't parse as a known wildcard is treated as a
    // real address.
    let after_scheme = match uri.split_once("://") {
        Some((_, rest)) => rest,
        None => return false,
    };
    after_scheme.starts_with("0.0.0.0:")
        || after_scheme.starts_with("[::]:")
        || after_scheme.starts_with("::")
}

/// How far a transport URI's host address can be reached from.
///
/// The point is not what the address *is* but who could dial it. An address
/// only says where a node lives relative to the speaker, and peer gossip
/// carries it verbatim across the internet, where most of that meaning is
/// lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReach {
    /// Points at the reading machine itself (`127/8`, `::1`).
    ///
    /// This can never identify a DIFFERENT node: whoever sent it meant their
    /// own machine, and here it means ours. Same argument as
    /// [`is_wildcard_transport`], which the code already acts on.
    Loopback,
    /// Private, link-local or unique-local: real, but only inside one network
    /// (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `fc00::/7`,
    /// `fe80::/10`).
    SiteLocal,
    /// Globally routable — or a hostname, which we do not resolve here and
    /// must not condemn on suspicion.
    Global,
}

/// Classify the host part of a transport URI.
///
/// Anything that is not a literal IP is [`HostReach::Global`]: a name may
/// resolve anywhere, and resolving it here would put a DNS lookup on a path
/// that walks every stored peer.
pub fn host_reach(uri: &str) -> HostReach {
    let Some((_, rest)) = uri.split_once("://") else {
        return HostReach::Global;
    };
    // `[2001:db8::1]:9000` — bracketed IPv6 with a port. Bare `::1` style
    // hosts without brackets are ambiguous with the port separator, so only
    // the bracketed form is read as v6.
    let host = if let Some(stripped) = rest.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, _)) => h,
            None => return HostReach::Global,
        }
    } else {
        rest.split(':').next().unwrap_or(rest)
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            if v4.is_loopback() {
                HostReach::Loopback
            } else if v4.is_private() || v4.is_link_local() {
                HostReach::SiteLocal
            } else {
                HostReach::Global
            }
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                HostReach::Loopback
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
            {
                // `Ipv6Addr::is_unique_local` / `is_unicast_link_local` are
                // still unstable; the prefix test is what they do.
                HostReach::SiteLocal
            } else {
                HostReach::Global
            }
        }
        Err(_) => HostReach::Global,
    }
}

/// Would dialling this address from here be pointless?
///
/// `we_are_site_local` is this node's own posture: true when we present a
/// private address to peers, i.e. we live on a LAN and a neighbour's private
/// address is plausibly ours to reach.
///
/// A seed that advertises a public address collects other people's LAN
/// addresses through peer gossip and can never dial one — a production seed
/// held 149 entries for `192.168.1.70:5599`, somebody else's home network,
/// plus 573 for `127.0.0.1`. Those are not merely useless: every one becomes
/// an outbound dial attempt on the next restart, and the loopback ones knock
/// on our own listener.
///
/// ⚠️ The posture test is an APPROXIMATION. Two nodes on two DIFFERENT private
/// networks both answer `true` and will keep each other's unreachable
/// addresses. Deciding it exactly needs to know which peer told us — and the
/// gossip channel carries only `node_id` and `transport`, so the answer is not
/// available where the decision is made. NAT'd peers are reached through a
/// relay, not by dialling what they advertise.
pub fn is_undialable_from_here(uri: &str, we_are_site_local: bool) -> bool {
    match host_reach(uri) {
        HostReach::Loopback => true,
        HostReach::SiteLocal => !we_are_site_local,
        HostReach::Global => false,
    }
}

/// Decode `relay` node-ids from listen config entries.
///
/// Returns a deduplicated list of 32-byte node-ids to include in
/// `RouteResponsePayload.relay_ids`.  Invalid or missing entries are
/// silently skipped (errors are caught at config-validation time).
pub fn build_relay_node_ids(config: &Config) -> Vec<[u8; 32]> {
    let mut seen = std::collections::HashSet::new();
    config
        .listen
        .iter()
        .filter_map(|l| l.relay.as_ref())
        .filter_map(|r| {
            base64::engine::general_purpose::STANDARD
                .decode(r)
                .ok()
                .and_then(|b| b.try_into().ok())
        })
        .filter(|id: &[u8; 32]| seen.insert(*id))
        .collect()
}

/// Parse `routing.target_labels` (`Vec<String>`) into wire-format
/// `[u8; LABEL_WIDTH]` entries.  Each label must be exactly 4 ASCII
/// bytes; shorter ones are zero-padded, longer ones truncated to keep the
/// wire layout fixed.  Duplicates are deduplicated; the list is capped
/// at `MAX_TARGET_LABELS`.  Operators set this in TOML as e.g.
/// `routing.target_labels = ["exit", "low", "qiwi"]`.
pub fn build_target_labels(routing: &veil_cfg::RoutingConfig) -> Vec<[u8; LABEL_WIDTH]> {
    let mut seen = std::collections::HashSet::new();
    routing
        .target_labels
        .iter()
        .map(|s| {
            let mut buf = [0u8; LABEL_WIDTH];
            let bytes = s.as_bytes();
            let n = bytes.len().min(LABEL_WIDTH);
            buf[..n].copy_from_slice(&bytes[..n]);
            buf
        })
        .filter(|l| seen.insert(*l))
        .take(MAX_TARGET_LABELS)
        .collect()
}

#[cfg(test)]
mod reach_tests {
    use super::*;

    #[test]
    fn loopback_is_recognised_in_both_families() {
        assert_eq!(host_reach("tcp://127.0.0.1:9000"), HostReach::Loopback);
        assert_eq!(host_reach("tcp://127.5.4.3:9000"), HostReach::Loopback);
        assert_eq!(host_reach("tcp://[::1]:9000"), HostReach::Loopback);
    }

    #[test]
    fn the_three_private_ranges_and_link_local_are_site_local() {
        assert_eq!(host_reach("tcp://10.0.0.1:9000"), HostReach::SiteLocal);
        assert_eq!(host_reach("tcp://172.16.4.4:9000"), HostReach::SiteLocal);
        assert_eq!(host_reach("tcp://192.168.1.70:5599"), HostReach::SiteLocal);
        assert_eq!(host_reach("tcp://169.254.7.7:9000"), HostReach::SiteLocal);
        assert_eq!(host_reach("tcp://[fc00::1]:9000"), HostReach::SiteLocal);
        assert_eq!(host_reach("tcp://[fe80::1]:9000"), HostReach::SiteLocal);
    }

    /// `172.16/12` ends at `172.31`. Getting the mask wrong here would
    /// condemn a public address, which is worse than keeping a useless one.
    #[test]
    fn the_edges_of_the_private_ranges_are_not_overshot() {
        assert_eq!(host_reach("tcp://172.15.0.1:9000"), HostReach::Global);
        assert_eq!(host_reach("tcp://172.32.0.1:9000"), HostReach::Global);
        assert_eq!(host_reach("tcp://11.0.0.1:9000"), HostReach::Global);
        assert_eq!(host_reach("tcp://192.169.1.1:9000"), HostReach::Global);
    }

    /// A hostname is not condemned on suspicion: we do not resolve here, and a
    /// name may point anywhere.
    #[test]
    fn a_hostname_is_treated_as_global() {
        assert_eq!(host_reach("tcp://seed.example.org:9000"), HostReach::Global);
        assert_eq!(
            host_reach("obfs4-tcp://203.0.113.146:5557"),
            HostReach::Global
        );
        assert_eq!(host_reach("not-a-uri"), HostReach::Global);
    }

    /// Loopback goes whatever this node is; a private address survives only
    /// where it could plausibly be dialled.
    #[test]
    fn posture_decides_private_but_never_loopback() {
        for site_local in [false, true] {
            assert!(
                is_undialable_from_here("tcp://127.0.0.1:9000", site_local),
                "a loopback address cannot name another node, whatever we are"
            );
            assert!(
                !is_undialable_from_here("tcp://203.0.113.146:5557", site_local),
                "a public address is always worth keeping"
            );
        }
        assert!(
            is_undialable_from_here("tcp://192.168.1.70:5599", false),
            "a node on the public internet can never reach somebody's LAN"
        );
        assert!(
            !is_undialable_from_here("tcp://192.168.1.70:5599", true),
            "a node on a LAN must keep its neighbours"
        );
    }
}
