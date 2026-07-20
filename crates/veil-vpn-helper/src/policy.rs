use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;

pub(crate) const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ROUTES: usize = 12_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HelperConfig {
    pub(crate) host_pid: u32,
    pub(crate) token: String,
    pub(crate) socks5_listen: String,
    pub(crate) policy: RoutingPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RoutingPolicy {
    route_mode: String,
    #[serde(default)]
    included_cidrs: Vec<String>,
    #[serde(default)]
    excluded_cidrs: Vec<String>,
    route_dns: bool,
    dns_servers: Vec<String>,
    allow_lan: bool,
    mtu: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteMode {
    AllTraffic,
    IncludeOnly,
    ExcludeOnly,
}

#[derive(Debug)]
pub(crate) struct ValidatedPolicy {
    pub(crate) route_mode: RouteMode,
    pub(crate) included: Vec<IpNet>,
    pub(crate) excluded: Vec<IpNet>,
    pub(crate) route_dns: bool,
    pub(crate) dns_servers: Vec<IpAddr>,
    pub(crate) mtu: u16,
}

impl HelperConfig {
    pub(crate) fn validate(&self) -> Result<ValidatedPolicy, String> {
        if self.host_pid == 0 {
            return Err("hostPid must be non-zero".to_owned());
        }
        if self.token.len() != 64
            || !self
                .token
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
        {
            return Err("token must be 32 lowercase hexadecimal bytes".to_owned());
        }
        if !(1280..=9000).contains(&self.policy.mtu) {
            return Err("MTU must be 1280...9000".to_owned());
        }
        let route_mode = match self.policy.route_mode.as_str() {
            "allTraffic" => RouteMode::AllTraffic,
            "includeOnly" => RouteMode::IncludeOnly,
            "excludeOnly" => RouteMode::ExcludeOnly,
            _ => return Err("unknown route mode".to_owned()),
        };
        if self.policy.included_cidrs.len() > MAX_ROUTES
            || self.policy.excluded_cidrs.len() > MAX_ROUTES
        {
            return Err("too many routes".to_owned());
        }
        let mut included = parse_routes(&self.policy.included_cidrs)?;
        let mut excluded = parse_routes(&self.policy.excluded_cidrs)?;
        if route_mode == RouteMode::IncludeOnly && included.is_empty() {
            return Err("include-only mode needs at least one route".to_owned());
        }
        let dns_servers = self
            .policy
            .dns_servers
            .iter()
            .map(|value| {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid DNS server: {value}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.policy.route_dns && dns_servers.is_empty() {
            return Err("routed DNS needs at least one server".to_owned());
        }
        if self.policy.allow_lan {
            excluded.extend(parse_routes(&[
                "10.0.0.0/8".to_owned(),
                "169.254.0.0/16".to_owned(),
                "172.16.0.0/12".to_owned(),
                "192.168.0.0/16".to_owned(),
                "fc00::/7".to_owned(),
                "fe80::/10".to_owned(),
            ])?);
        }
        if self.policy.route_dns && route_mode == RouteMode::IncludeOnly {
            included.extend(dns_servers.iter().map(|address| IpNet::from(*address)));
        }
        deduplicate(&mut included);
        deduplicate(&mut excluded);
        if included.len() > MAX_ROUTES || excluded.len() > MAX_ROUTES {
            return Err("expanded route policy is too large".to_owned());
        }
        Ok(ValidatedPolicy {
            route_mode,
            included,
            excluded,
            route_dns: self.policy.route_dns,
            dns_servers,
            mtu: self.policy.mtu,
        })
    }
}

fn parse_routes(values: &[String]) -> Result<Vec<IpNet>, String> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map(|network| network.trunc())
                .map_err(|_| format!("invalid CIDR: {value}"))
        })
        .collect()
}

fn deduplicate(routes: &mut Vec<IpNet>) {
    let mut seen = HashSet::with_capacity(routes.len());
    routes.retain(|route| seen.insert(*route));
    routes.sort_by_key(|route| (route.addr().is_ipv6(), route.prefix_len(), route.addr()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(route_mode: &str) -> HelperConfig {
        HelperConfig {
            host_pid: 42,
            token: "ab".repeat(32),
            socks5_listen: "127.0.0.1:1080".to_owned(),
            policy: RoutingPolicy {
                route_mode: route_mode.to_owned(),
                included_cidrs: Vec::new(),
                excluded_cidrs: Vec::new(),
                route_dns: true,
                dns_servers: vec!["1.1.1.1".to_owned()],
                allow_lan: false,
                mtu: 1500,
            },
        }
    }

    #[test]
    fn validates_closed_policy_and_normalizes_networks() {
        let mut value = config("includeOnly");
        value.policy.included_cidrs = vec!["10.2.3.4/8".to_owned(), "10.0.0.0/8".to_owned()];
        let policy = value.validate().unwrap();
        assert_eq!(value.socks5_listen, "127.0.0.1:1080");
        assert_eq!(MAX_CONFIG_BYTES, 2 * 1024 * 1024);
        assert_eq!(policy.route_mode, RouteMode::IncludeOnly);
        assert!(policy.route_dns);
        assert_eq!(
            policy.dns_servers,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(policy.mtu, 1500);
        assert_eq!(
            policy.included,
            vec!["10.0.0.0/8".parse().unwrap(), "1.1.1.1/32".parse().unwrap()]
        );
    }

    #[test]
    fn rejects_empty_include_only_and_noncanonical_token() {
        assert!(config("includeOnly").validate().is_err());
        let mut value = config("allTraffic");
        value.token = "AB".repeat(32);
        assert!(value.validate().is_err());
    }

    #[test]
    fn expands_lan_bypass_without_duplicates() {
        let mut value = config("excludeOnly");
        value.policy.allow_lan = true;
        value.policy.excluded_cidrs = vec!["192.168.1.2/16".to_owned()];
        let policy = value.validate().unwrap();
        assert_eq!(
            policy
                .excluded
                .iter()
                .filter(|route| route.to_string() == "192.168.0.0/16")
                .count(),
            1
        );
    }
}
