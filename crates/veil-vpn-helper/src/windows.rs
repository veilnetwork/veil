use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::time::Duration;

use ipnet::IpNet;
use serde::Serialize;
use tokio::runtime::Runtime;
use tun::{AbstractDevice, Layer};
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, CancellationToken, Error as TunnelError};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, MIB_IPPROTO_NETMGMT,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW, WaitForSingleObject,
};

use crate::policy::{HelperConfig, MAX_CONFIG_BYTES, RouteMode, ValidatedPolicy};

const TUN_NAME: &str = "xVeil VPN";
const TUN_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
const TUN_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);
const ROUTE_METRIC: u32 = 1;

struct Handle(HANDLE);

// SAFETY: Handle owns a process/token kernel handle. Windows handles may be
// waited on and closed from a different thread, and ownership is moved into
// the control thread rather than shared without synchronization.
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper exclusively owns a live Win32 handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct RouteGuard {
    rows: Vec<MIB_IPFORWARD_ROW2>,
    tunnel_index: u32,
}

impl RouteGuard {
    fn new(tunnel_index: u32) -> Self {
        Self {
            rows: Vec::new(),
            tunnel_index,
        }
    }

    fn add(&mut self, row: MIB_IPFORWARD_ROW2) -> Result<(), String> {
        // SAFETY: `row` is initialized according to the IP Helper contract.
        let status = unsafe { CreateIpForwardEntry2(&row) };
        if status == 0 {
            self.rows.push(row);
            return Ok(());
        }
        // A pre-existing physical route belongs to the user/system. It already
        // provides the requested bypass and must not be deleted during cleanup.
        if status == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(());
        }
        Err(format!("create Windows route failed ({status})"))
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for row in self.rows.iter().rev() {
            // SAFETY: the copied row is the exact entry created by this guard.
            let _ = unsafe { DeleteIpForwardEntry2(row) };
        }
        clear_dns_servers(self.tunnel_index);
    }
}

#[derive(Clone, Copy)]
struct PhysicalRoute {
    interface_index: u32,
    next_hop: SOCKADDR_INET,
}

#[derive(Clone, Copy, Default)]
struct PhysicalDefaults {
    ipv4: Option<PhysicalRoute>,
    ipv6: Option<PhysicalRoute>,
}

impl PhysicalDefaults {
    fn get(self, address: IpAddr) -> Option<PhysicalRoute> {
        if address.is_ipv4() {
            self.ipv4
        } else {
            self.ipv6
        }
    }
}

#[derive(Serialize)]
struct Status<'a> {
    phase: &'a str,
    token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

pub(crate) fn run(config_path: PathBuf) -> Result<i32, String> {
    if config_path.as_os_str().is_empty() {
        return Err("empty Windows VPN request path".to_owned());
    }
    let (config, request_dir) = load_config(&config_path)?;
    let status_path = request_dir.join("status.json");
    let stop_path = request_dir.join("stop");
    let result = run_inner(&config, &config_path, &stop_path, &status_path);
    if let Err(error) = &result {
        let _ = write_status(&status_path, &config.token, "error", Some(error));
    }
    result.map(|()| 0)
}

fn run_inner(
    config: &HelperConfig,
    config_path: &Path,
    stop_path: &Path,
    status_path: &Path,
) -> Result<(), String> {
    require_elevated()?;
    let policy = config.validate()?;
    let host = validate_host(config.host_pid)?;
    let defaults = snapshot_physical_defaults();
    validate_physical_bypasses(&policy, defaults)?;
    let args = tunnel_args(config, &policy)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| format!("create Windows packet runtime: {error}"))?;

    let device = create_tun(&runtime, &policy)?;
    let tunnel_index = device
        .tun_index()
        .map_err(|error| format!("read Wintun interface index: {error}"))?;
    let tunnel_index = u32::try_from(tunnel_index)
        .ok()
        .filter(|index| *index != 0)
        .ok_or_else(|| "Wintun returned an invalid interface index".to_owned())?;
    cleanup_stale_tunnel_routes(tunnel_index)?;
    if !policy.route_dns {
        clear_dns_servers(tunnel_index);
    }
    let mut routes = RouteGuard::new(tunnel_index);
    install_routes(&policy, defaults, tunnel_index, &mut routes)?;

    let _ = fs::remove_file(config_path);
    let _ = fs::remove_file(stop_path);
    let cancel = CancellationToken::new();
    let monitor_cancel = cancel.clone();
    let monitor_stop = stop_path.to_owned();
    write_status(status_path, &config.token, "running", None)?;
    let monitor = std::thread::Builder::new()
        .name("xveil-vpn-windows-control".to_owned())
        .spawn(move || monitor_host(host, &monitor_stop, monitor_cancel))
        .map_err(|error| format!("start Windows VPN control thread: {error}"))?;

    let tunnel_result = runtime.block_on(tun2proxy::run(device, policy.mtu, args, cancel.clone()));
    cancel.cancel();
    monitor
        .join()
        .map_err(|_| "Windows VPN control thread panicked".to_owned())?;
    drop(routes);
    match tunnel_result {
        Ok(_) => {}
        Err(TunnelError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(format!("Windows packet tunnel failed: {error}")),
    }
    write_status(status_path, &config.token, "stopped", None)?;
    Ok(())
}

fn load_config(path: &Path) -> Result<(HelperConfig, PathBuf), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read Windows VPN request metadata: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Windows VPN request must be a regular file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err("Windows VPN request has invalid size".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "Windows VPN request has no parent directory".to_owned())?
        .canonicalize()
        .map_err(|error| format!("resolve Windows VPN request directory: {error}"))?;
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("resolve Windows VPN request: {error}"))?;
    if canonical.parent() != Some(parent.as_path()) {
        return Err("Windows VPN request escaped its session directory".to_owned());
    }
    let bytes =
        fs::read(&canonical).map_err(|error| format!("read Windows VPN request: {error}"))?;
    let config = serde_json::from_slice::<HelperConfig>(&bytes)
        .map_err(|error| format!("parse Windows VPN request: {error}"))?;
    Ok((config, parent))
}

fn require_elevated() -> Result<(), String> {
    let mut token = ptr::null_mut();
    // SAFETY: output is a valid pointer and the pseudo process handle is live.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "open Windows process token: {}",
            io::Error::last_os_error()
        ));
    }
    let token = Handle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: buffer size exactly matches TOKEN_ELEVATION.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if ok == 0 || elevation.TokenIsElevated == 0 {
        return Err("Windows VPN helper requires administrator elevation".to_owned());
    }
    Ok(())
}

fn validate_host(host_pid: u32) -> Result<Handle, String> {
    // SAFETY: PID is data from a validated bounded request.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            host_pid,
        )
    };
    if raw.is_null() {
        return Err(format!(
            "open xVeil host process: {}",
            io::Error::last_os_error()
        ));
    }
    let handle = Handle(raw);
    let host_exe = process_image(handle.0)?;
    let current_exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("resolve elevated xVeil executable: {error}"))?;
    let host_exe = fs::canonicalize(host_exe)
        .map_err(|error| format!("resolve host xVeil executable: {error}"))?;
    if !host_exe
        .to_string_lossy()
        .eq_ignore_ascii_case(&current_exe.to_string_lossy())
    {
        return Err("Windows VPN host executable does not match helper".to_owned());
    }
    Ok(handle)
}

fn process_image(process: HANDLE) -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    // SAFETY: buffer and length are valid for the duration of the call.
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(format!(
            "query xVeil host executable: {}",
            io::Error::last_os_error()
        ));
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn snapshot_physical_defaults() -> PhysicalDefaults {
    PhysicalDefaults {
        ipv4: best_route(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        ipv6: best_route(IpAddr::V6("2606:4700:4700::1111".parse().unwrap())),
    }
}

fn best_route(destination: IpAddr) -> Option<PhysicalRoute> {
    let destination = sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: all pointers refer to initialized stack storage.
    let status = unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    (status == 0 && route.InterfaceIndex != 0).then_some(PhysicalRoute {
        interface_index: route.InterfaceIndex,
        next_hop: route.NextHop,
    })
}

fn validate_physical_bypasses(
    policy: &ValidatedPolicy,
    defaults: PhysicalDefaults,
) -> Result<(), String> {
    for route in &policy.excluded {
        if defaults.get(route.addr()).is_none() {
            return Err(format!(
                "no physical interface is available for excluded route {route}"
            ));
        }
    }
    if !policy.route_dns
        && let Some(dns) = policy.dns_servers.first()
        && defaults.get(*dns).is_none()
    {
        return Err(format!(
            "no physical interface is available for direct DNS {dns}"
        ));
    }
    Ok(())
}

fn tunnel_args(config: &HelperConfig, policy: &ValidatedPolicy) -> Result<Args, String> {
    let proxy_url = format!("socks5://{}", config.socks5_listen);
    let proxy = match ArgProxy::try_from(proxy_url.as_str()) {
        Ok(value) if value.addr.ip().is_loopback() => value,
        _ => return Err("Windows VPN requires a loopback SOCKS5 listener".to_owned()),
    };
    let dns_addr = policy
        .dns_servers
        .first()
        .copied()
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    Ok(Args {
        proxy,
        dns: if policy.route_dns {
            ArgDns::OverTcp
        } else {
            ArgDns::Direct
        },
        dns_addr,
        ipv6_enabled: true,
        setup: false,
        mtu: policy.mtu,
        verbosity: ArgVerbosity::Warn,
        ..Args::default()
    })
}

fn create_tun(runtime: &Runtime, policy: &ValidatedPolicy) -> Result<tun::AsyncDevice, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve xVeil executable directory: {error}"))?;
    let wintun = executable
        .parent()
        .ok_or_else(|| "xVeil executable has no parent directory".to_owned())?
        .join("wintun.dll");
    if !wintun.is_file() {
        return Err(format!("Wintun driver is missing: {}", wintun.display()));
    }
    let mut config = tun::Configuration::default();
    config
        .tun_name(TUN_NAME)
        .address(TUN_ADDRESS)
        .netmask(TUN_NETMASK)
        .mtu(policy.mtu)
        .layer(Layer::L3)
        .up();
    config.platform_config(|platform| {
        platform.wintun_file(&wintun);
        platform.wait_for_interfaces(true, false, Duration::from_secs(10));
        if policy.route_dns {
            platform.dns_servers(&policy.dns_servers);
        }
    });
    let _runtime_context = runtime.enter();
    tun::create_as_async(&config).map_err(|error| format!("create Wintun adapter: {error}"))
}

fn cleanup_stale_tunnel_routes(tunnel_index: u32) -> Result<(), String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    // SAFETY: output is a valid table pointer initialized by IP Helper.
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if status != 0 {
        return Err(format!("enumerate stale Wintun routes failed ({status})"));
    }
    if table.is_null() {
        return Ok(());
    }
    // SAFETY: IP Helper allocated one flexible array with NumEntries rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    for row in rows {
        if row.InterfaceIndex == tunnel_index && row.Protocol == MIB_IPPROTO_NETMGMT {
            // SAFETY: row is a live table entry copied by the API.
            let _ = unsafe { DeleteIpForwardEntry2(row) };
        }
    }
    // SAFETY: table came from GetIpForwardTable2 and is freed exactly once.
    unsafe { FreeMibTable(table.cast()) };
    Ok(())
}

fn install_routes(
    policy: &ValidatedPolicy,
    defaults: PhysicalDefaults,
    tunnel_index: u32,
    guard: &mut RouteGuard,
) -> Result<(), String> {
    let tunnel_routes = match policy.route_mode {
        RouteMode::IncludeOnly => policy.included.clone(),
        RouteMode::AllTraffic | RouteMode::ExcludeOnly => vec![
            "0.0.0.0/1".parse().unwrap(),
            "128.0.0.0/1".parse().unwrap(),
            "::/1".parse().unwrap(),
            "8000::/1".parse().unwrap(),
        ],
    };
    for route in tunnel_routes {
        guard.add(route_row(tunnel_index, route, None))?;
    }
    for route in &policy.excluded {
        let physical = defaults
            .get(route.addr())
            .ok_or_else(|| format!("no physical route for {route}"))?;
        guard.add(route_row(
            physical.interface_index,
            *route,
            Some(physical.next_hop),
        ))?;
    }
    if policy.route_dns {
        for dns in policy.dns_servers.iter().copied() {
            guard.add(route_row(tunnel_index, IpNet::from(dns), None))?;
        }
    }
    if !policy.route_dns
        && let Some(dns) = policy.dns_servers.first().copied()
    {
        let physical = defaults
            .get(dns)
            .ok_or_else(|| format!("no physical route for direct DNS {dns}"))?;
        guard.add(route_row(
            physical.interface_index,
            IpNet::from(dns),
            Some(physical.next_hop),
        ))?;
    }
    Ok(())
}

fn route_row(
    interface_index: u32,
    destination: IpNet,
    next_hop: Option<SOCKADDR_INET>,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: row is valid writable storage for initialization.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix.Prefix = sockaddr(destination.addr());
    row.DestinationPrefix.PrefixLength = destination.prefix_len();
    row.NextHop = next_hop.unwrap_or_else(|| unspecified_sockaddr(destination.addr()));
    row.Metric = ROUTE_METRIC;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

fn sockaddr(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

fn unspecified_sockaddr(family: IpAddr) -> SOCKADDR_INET {
    if family.is_ipv4() {
        sockaddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    } else {
        sockaddr(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }
}

fn monitor_host(host: Handle, stop_path: &Path, cancel: CancellationToken) {
    while !cancel.is_cancelled() {
        // SAFETY: the handle remains owned by this thread for the whole loop.
        if unsafe { WaitForSingleObject(host.0, 0) } != WAIT_TIMEOUT || stop_path.exists() {
            cancel.cancel();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn write_status(path: &Path, token: &str, phase: &str, detail: Option<&str>) -> Result<(), String> {
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(&Status {
        phase,
        token,
        detail,
    })
    .map_err(|error| format!("encode Windows VPN status: {error}"))?;
    fs::write(&temp, bytes).map_err(|error| format!("write Windows VPN status: {error}"))?;
    let _ = fs::remove_file(path);
    fs::rename(&temp, path).map_err(|error| format!("publish Windows VPN status: {error}"))
}

fn clear_dns_servers(interface_index: u32) {
    for family in ["ipv4", "ipv6"] {
        let _ = Command::new("netsh.exe")
            .args([
                "interface",
                family,
                "delete",
                "dnsservers",
                &format!("name={interface_index}"),
                "address=all",
                "validate=no",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
