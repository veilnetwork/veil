//! Small URI и config-decoding helpers shared by the runtime hot path.
//!
//! All functions здесь are pure (no I/O, no locks) и stateless.  They
//! exist as а single home for low-level string / config parsing that
//! was previously sprinkled через the tail of runtime/mod.rs.

use base64::Engine as _;

use veil_cfg::{self, Config};
use veil_proto::budget::{LABEL_WIDTH, MAX_TARGET_LABELS};
use veil_proto::control::NatCandidate;
use veil_transport::TransportUri;

/// Rewrite а `TransportUri` template by substituting the `NatCandidate`'s
/// IP+port for the template's host+port.  Returns `None` для malformed
/// candidates (wrong addr length для the declared `atyp`), unknown `atyp`
/// values, или template variants where NAT promotion is not meaningful
/// (Unix / Socks / Ws — see `TransportUri::with_host_port`).
///
/// IPv6 hosts are wrapped в brackets так что the resulting URI parses
/// correctly when round-tripped через `TransportUri::parse` (`url::Url`
/// rejects bare colons в the host component).
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

/// True when `uri` carries the placeholder `:0` port that operators use в
/// sim configs к request "pick any free port".  Production deploys
/// typically use explicit ports или `advertise` overrides.
///
/// Avoids а full URI parse на the per-handshake hot path.  Accepts both
/// `tcp://host:0` и `tcp://[::]:0` — both end в the literal `:0` suffix.
pub fn uri_has_port_zero(uri: &str) -> bool {
    uri.ends_with(":0")
}

/// Extract the scheme prefix от а URI (`tcp://...` → `Some("tcp")`).
/// Returns `None` для malformed URIs without а `://` separator.
pub fn uri_scheme(uri: &str) -> Option<&str> {
    uri.split_once("://").map(|(scheme, _)| scheme)
}

/// True when `uri` parses as `tcp://<host>:<port>` и `<host>` is the
/// IPv4 / IPv6 wildcard (`0.0.0.0` или `::`).  Used к drop these entries
/// from the PEX advertise set since they're never reachable from peers.
pub fn is_wildcard_transport(uri: &str) -> bool {
    // Accept either "tcp://0.0.0.0:..." / "tcp://[::]:..." plus tls/ws
    // variants by checking the substring after the scheme separator.
    // Anything that doesn't parse as а known wildcard is treated as а
    // real address.
    let after_scheme = match uri.split_once("://") {
        Some((_, rest)) => rest,
        None => return false,
    };
    after_scheme.starts_with("0.0.0.0:")
        || after_scheme.starts_with("[::]:")
        || after_scheme.starts_with("::")
}

/// Decode `relay` node-ids from listen config entries.
///
/// Returns а deduplicated list of 32-byte node-ids к include в
/// `RouteResponsePayload.relay_ids`.  Invalid или missing entries are
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
/// bytes; shorter ones are zero-padded, longer ones truncated к keep the
/// wire layout fixed.  Duplicates are deduplicated; the list is capped
/// at `MAX_TARGET_LABELS`.  Operators set this в TOML as e.g.
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
