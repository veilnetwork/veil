//! Privileged Linux system-VPN helper, entered by re-executing the xVeil GUI
//! binary through `pkexec`.
//!
//! The packet engine itself runs in this root child. The unprivileged GUI and
//! its embedded Veil node are moved into a dedicated cgroup whose OUTPUT
//! packets receive an nftables mark and consult a snapshot of the pre-tunnel
//! routing table. Consequently overlay/bootstrap/QUIC sockets cannot recurse
//! into the TUN, while every other process follows the requested VPN routes.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tun2proxy::{CancellationToken, Error as Tun2ProxyError};

use super::tunnel_args;

const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ROUTES: usize = 12_000;
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_NAME: &str = "xveil-vpn";
const NFT_TABLE: &str = "xveil_vpn";
const ROUTE_TABLE: &str = "7665";
const ROUTE_MARK: &str = "0x7665";
const RULE_PRIORITY: &str = "7665";
const TUN_NAME: &str = "xveil0";

static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperConfig {
    host_pid: u32,
    socks5_listen: String,
    policy: RoutingPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoutingPolicy {
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
enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckedCidr {
    text: String,
    family: IpFamily,
    prefix: u8,
}

impl CheckedCidr {
    fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("CIDR lacks prefix: {value}"))?;
        let address = IpAddr::from_str(address).map_err(|_| format!("invalid CIDR: {value}"))?;
        let prefix = u8::from_str(prefix).map_err(|_| format!("invalid CIDR: {value}"))?;
        let (family, maximum) = match address {
            IpAddr::V4(_) => (IpFamily::V4, 32),
            IpAddr::V6(_) => (IpFamily::V6, 128),
        };
        if prefix > maximum {
            return Err(format!("invalid CIDR prefix: {value}"));
        }
        Ok(Self {
            text: value.to_owned(),
            family,
            prefix,
        })
    }

    fn root(&self) -> bool {
        self.prefix == 0
    }
}

impl HelperConfig {
    fn validate(&self) -> Result<ValidatedPolicy, String> {
        if self.host_pid == 0 {
            return Err("hostPid must be non-zero".to_owned());
        }
        if !(1280..=9000).contains(&self.policy.mtu) {
            return Err("MTU must be 1280...9000".to_owned());
        }
        if !matches!(
            self.policy.route_mode.as_str(),
            "allTraffic" | "includeOnly" | "excludeOnly"
        ) {
            return Err("unknown route mode".to_owned());
        }
        if self.policy.included_cidrs.len() > MAX_ROUTES
            || self.policy.excluded_cidrs.len() > MAX_ROUTES
        {
            return Err("too many routes".to_owned());
        }
        let mut included = self
            .policy
            .included_cidrs
            .iter()
            .map(|value| CheckedCidr::parse(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut excluded = self
            .policy
            .excluded_cidrs
            .iter()
            .map(|value| CheckedCidr::parse(value))
            .collect::<Result<Vec<_>, _>>()?;
        if self.policy.route_mode == "includeOnly" && included.is_empty() {
            return Err("include-only mode needs at least one route".to_owned());
        }

        let dns_servers = self
            .policy
            .dns_servers
            .iter()
            .map(|value| {
                IpAddr::from_str(value).map_err(|_| format!("invalid DNS server: {value}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.policy.route_dns && dns_servers.is_empty() {
            return Err("routed DNS needs at least one server".to_owned());
        }

        if self.policy.allow_lan {
            excluded.extend(
                [
                    "10.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "fc00::/7",
                    "fe80::/10",
                ]
                .into_iter()
                .map(CheckedCidr::parse)
                .collect::<Result<Vec<_>, _>>()?,
            );
        }
        if self.policy.route_dns && self.policy.route_mode == "includeOnly" {
            included.extend(dns_servers.iter().map(|address| CheckedCidr {
                text: format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                family: if address.is_ipv4() {
                    IpFamily::V4
                } else {
                    IpFamily::V6
                },
                prefix: if address.is_ipv4() { 32 } else { 128 },
            }));
        }

        deduplicate(&mut included);
        deduplicate(&mut excluded);
        if included.len() > MAX_ROUTES || excluded.len() > MAX_ROUTES {
            return Err("expanded route policy is too large".to_owned());
        }
        Ok(ValidatedPolicy {
            route_mode: self.policy.route_mode.clone(),
            included,
            excluded,
            route_dns: self.policy.route_dns,
            dns_servers,
            mtu: self.policy.mtu,
        })
    }
}

#[derive(Debug)]
struct ValidatedPolicy {
    route_mode: String,
    included: Vec<CheckedCidr>,
    excluded: Vec<CheckedCidr>,
    route_dns: bool,
    dns_servers: Vec<IpAddr>,
    mtu: u16,
}

fn deduplicate(routes: &mut Vec<CheckedCidr>) {
    routes.sort_by(|left, right| left.text.cmp(&right.text));
    routes.dedup_by(|left, right| left.text == right.text);
}

#[derive(Default)]
struct SystemGuard {
    host_pid: u32,
    helper_pid: u32,
    original_host_cgroup: Option<PathBuf>,
    original_helper_cgroup: Option<PathBuf>,
    helper_cgroup: Option<PathBuf>,
    nft_installed: bool,
    rules_installed: bool,
    resolver_configured: bool,
    bypass_routes: Vec<(IpFamily, String)>,
}

impl Drop for SystemGuard {
    fn drop(&mut self) {
        if self.resolver_configured {
            let _ = command("resolvectl", ["revert", TUN_NAME]);
        }
        for (family, cidr) in self.bypass_routes.iter().rev() {
            let _ = ip(*family, ["route", "del", cidr.as_str()]);
        }
        if self.nft_installed {
            let _ = command("nft", ["delete", "table", "inet", NFT_TABLE]);
        }
        if self.rules_installed {
            delete_rules();
            let _ = ip(IpFamily::V4, ["route", "flush", "table", ROUTE_TABLE]);
            let _ = ip(IpFamily::V6, ["route", "flush", "table", ROUTE_TABLE]);
        }
        if let Some(original) = &self.original_host_cgroup {
            let _ = fs::write(original.join("cgroup.procs"), self.host_pid.to_string());
        }
        if let Some(original) = &self.original_helper_cgroup {
            let _ = fs::write(original.join("cgroup.procs"), self.helper_pid.to_string());
        }
        if let Some(helper) = &self.helper_cgroup {
            let _ = fs::remove_dir(helper);
        }
    }
}

fn command<I, S>(program: &str, arguments: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(program).args(arguments).output()
}

fn checked_command<I, S>(program: &str, arguments: I) -> Result<Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = command(program, arguments).map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        return Ok(output);
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "{program} failed ({}): {}",
        output.status,
        detail.trim()
    ))
}

fn ip<I, S>(family: IpFamily, arguments: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("ip")
        .arg(match family {
            IpFamily::V4 => "-4",
            IpFamily::V6 => "-6",
        })
        .args(arguments)
        .output()
}

fn checked_ip<I, S>(family: IpFamily, arguments: I) -> Result<Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = ip(family, arguments).map_err(|error| format!("run ip: {error}"))?;
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "ip failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn invoked_uid() -> Result<u32, String> {
    let value =
        std::env::var("PKEXEC_UID").map_err(|_| "helper must be launched by pkexec".to_owned())?;
    value
        .parse::<u32>()
        .map_err(|_| "PKEXEC_UID is invalid".to_owned())
}

fn load_config(path: &Path) -> Result<HelperConfig, String> {
    let uid = invoked_uid()?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("read config metadata: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err("unsafe helper config ownership, type, size, or mode".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| format!("read helper config: {error}"))?;
    let _ = fs::remove_file(path);
    serde_json::from_slice(&bytes).map_err(|error| format!("parse helper config: {error}"))
}

fn validate_host(host_pid: u32, uid: u32) -> Result<(), String> {
    let status = fs::read_to_string(format!("/proc/{host_pid}/status"))
        .map_err(|error| format!("read host process: {error}"))?;
    let host_uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| "host process UID is unavailable".to_owned())?;
    if host_uid != uid {
        return Err("host process does not belong to the pkexec caller".to_owned());
    }
    let helper_exe = fs::canonicalize("/proc/self/exe")
        .map_err(|error| format!("resolve helper executable: {error}"))?;
    let host_exe = fs::canonicalize(format!("/proc/{host_pid}/exe"))
        .map_err(|error| format!("resolve host executable: {error}"))?;
    if helper_exe != host_exe {
        return Err("host and helper executables do not match".to_owned());
    }
    Ok(())
}

fn original_cgroup(host_pid: u32) -> Result<PathBuf, String> {
    let content = fs::read_to_string(format!("/proc/{host_pid}/cgroup"))
        .map_err(|error| format!("read host cgroup: {error}"))?;
    let relative = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "cgroup v2 is required".to_owned())?
        .trim_start_matches('/');
    let root = Path::new(CGROUP_ROOT);
    let path = root.join(relative);
    let canonical =
        fs::canonicalize(&path).map_err(|error| format!("resolve host cgroup: {error}"))?;
    if !canonical.starts_with(root) {
        return Err("host cgroup escaped cgroup root".to_owned());
    }
    Ok(canonical)
}

fn cleanup_stale() -> Result<(), String> {
    let helper = Path::new(CGROUP_ROOT).join(CGROUP_NAME);
    if helper.exists() {
        let procs = fs::read_to_string(helper.join("cgroup.procs"))
            .map_err(|error| format!("inspect existing VPN cgroup: {error}"))?;
        if !procs.trim().is_empty() {
            return Err("another xVeil VPN helper is active".to_owned());
        }
    }
    let _ = command("nft", ["delete", "table", "inet", NFT_TABLE]);
    delete_rules();
    let _ = ip(IpFamily::V4, ["route", "flush", "table", ROUTE_TABLE]);
    let _ = ip(IpFamily::V6, ["route", "flush", "table", ROUTE_TABLE]);
    let _ = fs::remove_dir(helper);
    Ok(())
}

fn delete_rules() {
    for family in [IpFamily::V4, IpFamily::V6] {
        for _ in 0..4 {
            let Ok(output) = ip(family, ["rule", "del", "priority", RULE_PRIORITY]) else {
                break;
            };
            if !output.status.success() {
                break;
            }
        }
    }
}

fn install_cgroup_mark(host_pid: u32, guard: &mut SystemGuard) -> Result<(), String> {
    let helper_pid = std::process::id();
    let original_host = original_cgroup(host_pid)?;
    let original_helper = original_cgroup(helper_pid)?;
    let helper = Path::new(CGROUP_ROOT).join(CGROUP_NAME);
    fs::create_dir(&helper).map_err(|error| format!("create VPN cgroup: {error}"))?;
    let existing = fs::read_to_string(helper.join("cgroup.procs")).unwrap_or_default();
    if existing
        .lines()
        .any(|line| line.trim() != host_pid.to_string())
    {
        return Err("another xVeil VPN cgroup is active".to_owned());
    }
    guard.host_pid = host_pid;
    guard.helper_pid = helper_pid;
    guard.original_host_cgroup = Some(original_host);
    guard.original_helper_cgroup = Some(original_helper);
    guard.helper_cgroup = Some(helper.clone());
    fs::write(helper.join("cgroup.procs"), host_pid.to_string())
        .map_err(|error| format!("move xVeil into VPN bypass cgroup: {error}"))?;
    fs::write(helper.join("cgroup.procs"), helper_pid.to_string())
        .map_err(|error| format!("move VPN helper into bypass cgroup: {error}"))?;

    let cgroup_id = fs::metadata(&helper)
        .map_err(|error| format!("inspect VPN cgroup: {error}"))?
        .ino();
    let script = format!(
        "add table inet {NFT_TABLE}\n\
         add chain inet {NFT_TABLE} output {{ type route hook output priority mangle; policy accept; }}\n\
         add rule inet {NFT_TABLE} output meta cgroup {cgroup_id} meta mark set {ROUTE_MARK}\n"
    );
    guard.nft_installed = true;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start nft: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "nft stdin unavailable".to_owned())?
        .write_all(script.as_bytes())
        .map_err(|error| format!("write nft rules: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for nft: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "install nft cgroup mark: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn copy_main_routes(family: IpFamily) -> Result<(), String> {
    let output = checked_ip(family, ["route", "show", "table", "main"])?;
    let routes = String::from_utf8(output.stdout).map_err(|_| "ip route output is not UTF-8")?;
    for line in routes
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut args = vec!["route", "add", "table", ROUTE_TABLE];
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        args.extend(tokens);
        let output = ip(family, args).map_err(|error| format!("copy route table: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "copy route into bypass table: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

fn install_bypass_table(guard: &mut SystemGuard) -> Result<(), String> {
    copy_main_routes(IpFamily::V4)?;
    copy_main_routes(IpFamily::V6)?;
    // Arm cleanup before the first add: a host without IPv6 policy support may
    // accept the IPv4 rule and reject the second command.
    guard.rules_installed = true;
    for family in [IpFamily::V4, IpFamily::V6] {
        checked_ip(
            family,
            [
                "rule",
                "add",
                "priority",
                RULE_PRIORITY,
                "fwmark",
                ROUTE_MARK,
                "lookup",
                ROUTE_TABLE,
            ],
        )?;
    }
    Ok(())
}

fn default_route_tail(family: IpFamily) -> Result<Option<Vec<String>>, String> {
    let output = checked_ip(family, ["route", "show", "default"])?;
    let text = String::from_utf8(output.stdout).map_err(|_| "default route is not UTF-8")?;
    Ok(text.lines().find_map(|line| {
        let mut tokens = line.split_whitespace();
        (tokens.next() == Some("default")).then(|| tokens.map(str::to_owned).collect())
    }))
}

fn install_bypass_routes(policy: &ValidatedPolicy, guard: &mut SystemGuard) -> Result<(), String> {
    for family in [IpFamily::V4, IpFamily::V6] {
        let Some(tail) = default_route_tail(family)? else {
            continue;
        };
        for cidr in policy.excluded.iter().filter(|cidr| cidr.family == family) {
            if cidr.root() {
                continue;
            }
            let mut args = vec!["route".to_owned(), "add".to_owned(), cidr.text.clone()];
            args.extend(tail.clone());
            let output = ip(family, &args).map_err(|error| format!("add bypass route: {error}"))?;
            if output.status.success() {
                guard.bypass_routes.push((family, cidr.text.clone()));
                continue;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                return Err(format!("add bypass route {}: {}", cidr.text, stderr.trim()));
            }
        }
    }
    Ok(())
}

fn install_tunnel_routes(policy: &ValidatedPolicy) -> Result<(), String> {
    let excludes_all_v4 = policy
        .excluded
        .iter()
        .any(|cidr| cidr.family == IpFamily::V4 && cidr.root());
    let excludes_all_v6 = policy
        .excluded
        .iter()
        .any(|cidr| cidr.family == IpFamily::V6 && cidr.root());

    let routes = if policy.route_mode == "includeOnly" {
        policy.included.clone()
    } else {
        let mut routes = Vec::new();
        if !excludes_all_v4 && default_route_tail(IpFamily::V4)?.is_some() {
            routes.extend([
                CheckedCidr::parse("0.0.0.0/1")?,
                CheckedCidr::parse("128.0.0.0/1")?,
            ]);
        }
        if !excludes_all_v6 && default_route_tail(IpFamily::V6)?.is_some() {
            routes.extend([CheckedCidr::parse("::/1")?, CheckedCidr::parse("8000::/1")?]);
        }
        routes
    };

    for cidr in routes {
        checked_ip(
            cidr.family,
            [
                "route",
                "add",
                cidr.text.as_str(),
                "dev",
                TUN_NAME,
                "metric",
                "1",
            ],
        )?;
    }
    Ok(())
}

fn configure_resolver(policy: &ValidatedPolicy, guard: &mut SystemGuard) -> Result<(), String> {
    if !policy.route_dns {
        return Ok(());
    }
    // `resolvectl dns` can succeed while a later domain/default-route command
    // fails. Revert the link even on that partial path.
    guard.resolver_configured = true;
    let mut dns_args = vec!["dns".to_owned(), TUN_NAME.to_owned()];
    dns_args.extend(policy.dns_servers.iter().map(ToString::to_string));
    checked_command("resolvectl", &dns_args)?;
    checked_command("resolvectl", ["domain", TUN_NAME, "~."])?;
    checked_command("resolvectl", ["default-route", TUN_NAME, "yes"])?;
    Ok(())
}

fn create_tun(mtu: u16) -> Result<tun::AsyncDevice, String> {
    let mut configuration = tun::Configuration::default();
    configuration
        .tun_name(TUN_NAME)
        .address((10, 118, 101, 2))
        .destination((10, 118, 101, 1))
        .netmask((255, 255, 255, 252))
        .mtu(mtu)
        .up();
    configuration.platform_config(|platform| {
        #[allow(deprecated)]
        platform.packet_information(true);
        platform.ensure_root_privileges(true);
    });
    tun::create_as_async(&configuration).map_err(|error| format!("create TUN: {error}"))
}

extern "C" fn stop_signal(_: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::Release);
}

fn install_signal_handlers() {
    SIGNAL_STOP.store(false, Ordering::Release);
    // SAFETY: the handler only performs an async-signal-safe atomic store.
    unsafe {
        libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            stop_signal as *const () as libc::sighandler_t,
        );
    }
}

fn emit_status(phase: &str, detail: Option<&str>) {
    let mut object = serde_json::Map::new();
    object.insert("phase".to_owned(), phase.into());
    if let Some(detail) = detail {
        object.insert("detail".to_owned(), detail.into());
    }
    println!("{}", serde_json::Value::Object(object));
    let _ = io::stdout().flush();
}

fn run_inner(config_path: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Linux VPN helper requires root".to_owned());
    }
    checked_command("ip", ["-Version"])
        .map_err(|_| "required Linux VPN tool is missing: ip".to_owned())?;
    checked_command("nft", ["--version"])
        .map_err(|_| "required Linux VPN tool is missing: nft".to_owned())?;
    let config = load_config(Path::new(config_path))?;
    let policy = config.validate()?;
    if policy.route_dns {
        checked_command("resolvectl", ["--version"])
            .map_err(|_| "routed DNS requires systemd-resolved/resolvectl".to_owned())?;
    }
    let uid = invoked_uid()?;
    validate_host(config.host_pid, uid)?;
    let proxy = format!("socks5://{}", config.socks5_listen);
    let dns = policy
        .dns_servers
        .first()
        .copied()
        .unwrap_or(IpAddr::from([1, 1, 1, 1]));
    let args = tunnel_args(&proxy, &dns.to_string(), policy.mtu, policy.route_dns)
        .map_err(|_| "invalid loopback SOCKS5 or packet-tunnel arguments".to_owned())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| format!("create packet runtime: {error}"))?;

    cleanup_stale()?;
    let mut guard = SystemGuard::default();
    install_cgroup_mark(config.host_pid, &mut guard)?;
    install_bypass_table(&mut guard)?;
    let device = {
        let _runtime_context = runtime.enter();
        create_tun(policy.mtu)?
    };
    install_bypass_routes(&policy, &mut guard)?;
    install_tunnel_routes(&policy)?;
    configure_resolver(&policy, &mut guard)?;

    install_signal_handlers();
    let cancel = CancellationToken::new();
    let stdin_cancel = cancel.clone();
    std::thread::Builder::new()
        .name("xveil-vpn-stdin".to_owned())
        .spawn(move || {
            let mut line = String::new();
            let _ = io::stdin().lock().read_line(&mut line);
            stdin_cancel.cancel();
        })
        .map_err(|error| format!("start helper control thread: {error}"))?;
    let signal_cancel = cancel.clone();
    std::thread::Builder::new()
        .name("xveil-vpn-signal".to_owned())
        .spawn(move || {
            while !SIGNAL_STOP.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(50));
            }
            signal_cancel.cancel();
        })
        .map_err(|error| format!("start helper signal thread: {error}"))?;

    emit_status("running", None);
    let result = runtime.block_on(tun2proxy::run(device, policy.mtu, args, cancel));
    match result {
        Ok(_) => {}
        Err(Tun2ProxyError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(format!("packet tunnel failed: {error}")),
    }
    drop(guard);
    emit_status("stopped", None);
    Ok(())
}

pub(super) fn run(config_path: &str) -> libc::c_int {
    match run_inner(config_path) {
        Ok(()) => crate::VEIL_OK,
        Err(error) => {
            emit_status("error", Some(&error));
            crate::VEIL_ERR
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;

    use super::*;

    const SMOKE_TEST: &str = "packet_tunnel::linux_helper::tests::privileged_route_lifecycle_smoke";

    fn config(mode: &str) -> HelperConfig {
        HelperConfig {
            host_pid: 42,
            socks5_listen: "127.0.0.1:1080".to_owned(),
            policy: RoutingPolicy {
                route_mode: mode.to_owned(),
                included_cidrs: Vec::new(),
                excluded_cidrs: Vec::new(),
                route_dns: true,
                dns_servers: vec!["1.1.1.1".to_owned(), "2606:4700:4700::1111".to_owned()],
                allow_lan: true,
                mtu: 1280,
            },
        }
    }

    #[test]
    fn include_only_requires_routes_and_adds_dns_hosts() {
        assert!(config("includeOnly").validate().is_err());
        let mut value = config("includeOnly");
        value.policy.included_cidrs = vec!["203.0.113.0/24".to_owned()];
        let policy = value.validate().unwrap();
        assert!(
            policy
                .included
                .iter()
                .any(|route| route.text == "1.1.1.1/32")
        );
        assert!(
            policy
                .included
                .iter()
                .any(|route| route.text == "2606:4700:4700::1111/128")
        );
    }

    #[test]
    fn lan_bypass_is_explicit_and_bounded() {
        let policy = config("allTraffic").validate().unwrap();
        assert!(
            policy
                .excluded
                .iter()
                .any(|route| route.text == "10.0.0.0/8")
        );
        assert!(policy.excluded.iter().any(|route| route.text == "fc00::/7"));
        assert!(policy.excluded.len() <= MAX_ROUTES);
    }

    #[test]
    fn rejects_invalid_cidrs_dns_and_mtu() {
        let mut value = config("excludeOnly");
        value.policy.excluded_cidrs = vec!["192.0.2.0/33".to_owned()];
        assert!(value.validate().is_err());
        value.policy.excluded_cidrs.clear();
        value.policy.dns_servers = vec!["resolver.invalid".to_owned()];
        assert!(value.validate().is_err());
        value.policy.dns_servers = vec!["1.1.1.1".to_owned()];
        value.policy.mtu = 1279;
        assert!(value.validate().is_err());
    }

    /// Exercises the real cgroup, nftables, policy-routing and TUN lifecycle.
    ///
    /// This is ignored because it intentionally requires root plus a private
    /// Linux network/cgroup namespace. CI or a developer can run it inside a
    /// privileged disposable container without changing the host's routes.
    #[test]
    #[ignore = "requires a privileged disposable Linux namespace"]
    fn privileged_route_lifecycle_smoke() {
        match std::env::var("XVEIL_VPN_SMOKE_ROLE").as_deref() {
            Ok("host") => {
                std::thread::sleep(Duration::from_secs(30));
                return;
            }
            Ok("helper") => {
                let config_path = std::env::var("XVEIL_VPN_SMOKE_CONFIG").unwrap();
                assert_eq!(run(&config_path), crate::VEIL_OK);
                return;
            }
            _ => {}
        }

        assert_eq!(unsafe { libc::geteuid() }, 0, "smoke test needs root");
        let executable = std::env::current_exe().unwrap();
        let mut host = Command::new(&executable);
        host.args([SMOKE_TEST, "--ignored", "--exact", "--nocapture"])
            .env("XVEIL_VPN_SMOKE_ROLE", "host")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        host.uid(1000);
        let mut host = host.spawn().unwrap();

        let mut request = tempfile::NamedTempFile::new().unwrap();
        let body = serde_json::json!({
            "hostPid": host.id(),
            "socks5Listen": "127.0.0.1:1080",
            "policy": {
                "routeMode": "includeOnly",
                "includedCidrs": ["198.51.100.0/24"],
                "excludedCidrs": [],
                "routeDns": false,
                "dnsServers": [],
                "allowLan": false,
                "mtu": 1280
            }
        });
        serde_json::to_writer(&mut request, &body).unwrap();
        request.flush().unwrap();
        let request_path = request.path().to_owned();
        let request_path_c =
            std::ffi::CString::new(request_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path CString is valid for this call and UID 1000 is the
        // deliberately unprivileged GUI identity used by this isolated test.
        assert_eq!(
            unsafe { libc::chown(request_path_c.as_ptr(), 1000, 1000) },
            0
        );

        let output = Command::new(&executable)
            .args([SMOKE_TEST, "--ignored", "--exact", "--nocapture"])
            .env("XVEIL_VPN_SMOKE_ROLE", "helper")
            .env("XVEIL_VPN_SMOKE_CONFIG", &request_path)
            .env("PKEXEC_UID", "1000")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let _ = host.kill();
        let _ = host.wait();

        assert!(
            output.status.success(),
            "helper failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("\"phase\":\"running\""), "{stdout}");
        assert!(stdout.contains("\"phase\":\"stopped\""), "{stdout}");
        assert!(!Path::new(CGROUP_ROOT).join(CGROUP_NAME).exists());
        assert!(
            !command("nft", ["list", "table", "inet", NFT_TABLE])
                .unwrap()
                .status
                .success()
        );
    }
}
