use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
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
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_OBJECT_ALREADY_EXISTS, ERROR_PIPE_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, MIB_IPPROTO_NETMGMT,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, PIPE_ACCESS_INBOUND, ReadFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE, PIPE_WAIT,
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

pub(crate) fn run(config_path: PathBuf, expected_sha256: &str) -> Result<i32, String> {
    if config_path.as_os_str().is_empty() {
        return Err("empty Windows VPN request path".to_owned());
    }
    let (config, request_dir) = load_config(&config_path, expected_sha256)?;
    // NOT in the session directory. See [protected_status_dir]: what the host
    // reads back has to come from somewhere that user cannot write.
    let status_dir = protected_status_dir(&request_dir)?;
    let status_path = status_dir.join("status.json");
    // The stop travels on a named pipe named after this session, not as a file
    // in it: see [stop_requested_by_host].
    let result = run_inner(&config, &config_path, &request_dir, &status_path);
    if let Err(error) = &result {
        let _ = write_status(&status_path, &config.token, "error", Some(error));
    }
    // The directory is this run's; nothing else may inherit it.
    let _ = fs::remove_file(&status_path);
    let _ = fs::remove_dir(&status_dir);
    result.map(|()| 0)
}

fn run_inner(
    config: &HelperConfig,
    config_path: &Path,
    session_dir: &Path,
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
    let cancel = CancellationToken::new();
    let monitor_cancel = cancel.clone();
    write_status(status_path, &config.token, "running", None)?;
    let monitor = std::thread::Builder::new()
        .name("xveil-vpn-windows-control".to_owned())
        .spawn(move || monitor_host(host, monitor_cancel))
        .map_err(|error| format!("start Windows VPN control thread: {error}"))?;
    // The explicit stop, on a pipe rather than a file: a file in a directory
    // the user can write is a stop button for every process of that user, and
    // taking down an administrator-level tunnel sends the traffic outside it.
    // The pipe is writable by that user too — same user, same access — but it
    // can say WHO connected, and only the host is accepted.
    let stop_pipe = control_pipe_name(session_dir).and_then(|name| {
        create_control_pipe(&name).map(|pipe| {
            let stop_cancel = cancel.clone();
            let host_pid = config.host_pid;
            std::thread::Builder::new()
                .name("xveil-vpn-windows-stop".to_owned())
                .spawn(move || monitor_control_pipe(pipe, host_pid, stop_cancel))
        })
    });

    let tunnel_result = runtime.block_on(tun2proxy::run(device, policy.mtu, args, cancel.clone()));
    cancel.cancel();
    monitor
        .join()
        .map_err(|_| "Windows VPN control thread panicked".to_owned())?;
    // NOT joined: the stop thread is parked in a blocking connect that only a
    // client can release, and the tunnel is already down. Its handle closes
    // with the process, which is moments away.
    drop(stop_pipe);
    drop(routes);
    match tunnel_result {
        Ok(_) => {}
        Err(TunnelError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(format!("Windows packet tunnel failed: {error}")),
    }
    write_status(status_path, &config.token, "stopped", None)?;
    Ok(())
}

fn load_config(path: &Path, expected_sha256: &str) -> Result<(HelperConfig, PathBuf), String> {
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
    // BEFORE it is parsed, and against the bytes actually read — not a second
    // read, which would leave the window this check exists to close. The host
    // hashed what it wrote and passed the digest on the elevated command line,
    // which nothing of the user's can change once UAC has returned.
    if !crate::integrity::digest_matches(expected_sha256, &bytes) {
        return Err(
            "Windows VPN request does not match the approved launch; refusing to apply it"
                .to_owned(),
        );
    }
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

/// The control pipe's security, and every clause of it is load-bearing.
///
///   `D:` SY/BA full, and `IU` (interactive users) read+write — the host is
///        UNELEVATED and has to be able to say "stop";
///   `S:(ML;;NW;;;ME)` a MEDIUM mandatory label. Without it the pipe inherits
///        this process's HIGH integrity, Windows' no-write-up rule applies,
///        and the very process that needs to write to it cannot.
///
/// Granting the interactive user write access grants it to EVERY process of
/// that user, which is why the DACL is not the check. The check is who is on
/// the other end: [`stop_requested_by_host`] asks the pipe for its client's
/// PID and accepts only the host this run was launched for.
const CONTROL_PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;ME)";

/// The control pipe for one run, named after its session directory.
fn control_pipe_name(session: &Path) -> Option<String> {
    let name = session.file_name()?.to_string_lossy().into_owned();
    // The session directory is already named `xveil-vpn-<random>`, so the
    // name goes in as it is rather than carrying the prefix twice.
    Some(format!(r"\\.\pipe\{name}"))
}

/// Create this run's control pipe, or None when it cannot be made.
///
/// None is not fatal: the host-exit watch still ends the tunnel, and a helper
/// that refused to run because a pipe would not open would be a worse failure
/// than one that cannot be asked to stop early.
fn create_control_pipe(name: &str) -> Option<Handle> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    let mut sddl: Vec<u16> = CONTROL_PIPE_SDDL.encode_utf16().collect();
    sddl.push(0);
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: both inputs are NUL-terminated UTF-16; the descriptor is an out
    // parameter freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return None;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is NUL-terminated and `attributes` outlives the call.
    // One instance: this run has exactly one host, and a second server would
    // be a second thing able to stop it.
    let pipe = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            0,
            64,
            0,
            &attributes,
        )
    };
    // SAFETY: the descriptor came from the converter, which allocates with
    // LocalAlloc.
    unsafe { LocalFree(descriptor as *mut _) };
    if pipe == INVALID_HANDLE_VALUE || pipe.is_null() {
        return None;
    }
    Some(Handle(pipe))
}

/// Wait for a stop from the HOST — and from nothing else.
///
/// The stop used to be a file in the session directory. That directory has to
/// be writable by the user (the host is unelevated when it stages the
/// request), so any process of that user could create the file and take down
/// an administrator-level tunnel — traffic then leaves outside it, which is
/// the part that matters (report5 R5-X-03).
///
/// A pipe cannot be locked to one process by permissions either: same user,
/// same access. What it can do that a file cannot is say WHO connected.
/// `GetNamedPipeClientProcessId` names the client, and the only client this
/// accepts is `host_pid` — the process whose image `validate_host` already
/// bound to this helper's own before anything was applied.
///
/// Returns true when the host asked to stop; false on any error, so a pipe
/// that cannot be created or read leaves the tunnel up rather than tearing it
/// down on a failure nobody asked for. The host-exit watch is unaffected and
/// remains the backstop.
fn stop_requested_by_host(pipe: HANDLE, host_pid: u32) -> bool {
    // SAFETY: `pipe` is a live server handle owned by the caller.
    let connected = unsafe { ConnectNamedPipe(pipe, ptr::null_mut()) };
    if connected == 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // ERROR_PIPE_CONNECTED: a client got there between the create and the
        // connect. That is a connection, not a failure.
        if err != ERROR_PIPE_CONNECTED as i32 {
            return false;
        }
    }
    let mut client = 0u32;
    // SAFETY: `client` is a valid out parameter for the duration of the call.
    let named = unsafe { GetNamedPipeClientProcessId(pipe, &mut client) };
    if named == 0 || client != host_pid {
        return false;
    }
    let mut buf = [0u8; 16];
    let mut read = 0u32;
    // SAFETY: the buffer outlives the call and its length is passed exactly.
    let ok = unsafe {
        ReadFile(
            pipe,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    };
    ok != 0 && buf[..read as usize].starts_with(b"stop")
}

fn monitor_host(host: Handle, cancel: CancellationToken) {
    while !cancel.is_cancelled() {
        // SAFETY: the handle remains owned by this thread for the whole loop.
        if unsafe { WaitForSingleObject(host.0, 0) } != WAIT_TIMEOUT {
            cancel.cancel();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The explicit stop, on its own thread because the connect blocks.
///
/// Separate from [`monitor_host`] deliberately: that one is the backstop and
/// must keep working whether or not a pipe could be made.
fn monitor_control_pipe(pipe: Handle, host_pid: u32, cancel: CancellationToken) {
    if stop_requested_by_host(pipe.0, host_pid) {
        cancel.cancel();
    }
}

/// The DACL every directory below carries, and it is PROTECTED (`D:P`) — it
/// inherits nothing from whatever the parent happens to grant.
///
///   SY  local SYSTEM          FA  full control
///   BA  builtin Administrators FA
///   BU  builtin Users          FR  read only
///
/// Read for Users on purpose: the host is UNELEVATED and has to poll the
/// status. What it must not be able to do — and what nothing running as that
/// user must be able to do — is write one.
const STATUS_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";

/// Create `path` with [STATUS_DIR_SDDL]. `Ok(false)` when it already existed.
fn create_protected_dir(path: &Path) -> Result<bool, String> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut sddl: Vec<u16> = STATUS_DIR_SDDL.encode_utf16().collect();
    sddl.push(0);
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: both inputs are NUL-terminated UTF-16; the descriptor is an out
    // parameter freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(format!(
            "build the Windows VPN status DACL: {}",
            io::Error::last_os_error()
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is NUL-terminated and `attributes` outlives the call.
    let made = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    let error = io::Error::last_os_error();
    // SAFETY: the descriptor came from the converter, which allocates with
    // LocalAlloc.
    unsafe { LocalFree(descriptor as *mut _) };
    if made != 0 {
        return Ok(true);
    }
    if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
        return Ok(false);
    }
    Err(format!("create {}: {error}", path.display()))
}

/// Where this run publishes its status: a directory only an elevated process
/// can write.
///
/// The status used to be written into the session directory in the user's own
/// %TEMP%, beside the request. That directory MUST be user-writable — the host
/// is unelevated when it stages the request — so any process of that user could
/// write a status of its own: a forged `running` for a tunnel that never came
/// up, or a forged `error` that makes the app tear down a working one. The
/// token in the status is no defence: it is in the request file, which the same
/// user can read.
///
/// So the direction that must not be forgeable — helper to host — moves under
/// %ProgramData%, where this process can write and that user cannot. The leaf
/// is named after the session directory, which is random per launch, and it
/// must NOT already exist: a name nobody can predict and a create that refuses
/// to reuse leaves nothing to squat on. Its DACL is protected, so a parent
/// somebody else made grants nothing here.
fn protected_status_dir(session: &Path) -> Result<PathBuf, String> {
    let program_data = std::env::var_os("ProgramData")
        .ok_or_else(|| "ProgramData is not set; refusing a forgeable status".to_owned())?;
    let name = session
        .file_name()
        .ok_or_else(|| "the Windows VPN session directory has no name".to_owned())?;
    let base = PathBuf::from(program_data).join("xVeil");
    let vpn = base.join("vpn");
    // The two parents may legitimately exist from an earlier run. Their DACL
    // does not matter to the leaf, which is protected.
    create_protected_dir(&base)?;
    create_protected_dir(&vpn)?;
    let leaf = vpn.join(name);
    if !create_protected_dir(&leaf)? {
        return Err(format!(
            "{} already exists; refusing to publish status into a directory \
             this run did not create",
            leaf.display()
        ));
    }
    // A parent somebody redirected cannot weaken the leaf's DACL, but it can
    // move it somewhere the host will never look. Say so rather than run blind.
    let meta = fs::metadata(&leaf).map_err(|e| format!("stat {}: {e}", leaf.display()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is a reparse point", leaf.display()));
    }
    Ok(leaf)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A well-formed request, as the host writes it.
    const REQUEST: &str = concat!(
        r#"{"hostPid":42,"token":"tok","socks5Listen":"127.0.0.1:1080","#,
        r#""policy":{"routeMode":"allTraffic","includedCidrs":[],"#,
        r#""excludedCidrs":[],"routeDns":true,"dnsServers":["1.1.1.1"],"#,
        r#""allowLan":false,"mtu":1500}}"#
    );

    /// The same request with ONE field changed — the SOCKS endpoint an
    /// administrator-level tunnel would be pointed at. This is the attack:
    /// same shape, same length class, different destination, swapped into the
    /// user's own %TEMP% while the UAC prompt is on screen.
    const TAMPERED: &str = concat!(
        r#"{"hostPid":42,"token":"tok","socks5Listen":"10.66.66.66:1080","#,
        r#""policy":{"routeMode":"allTraffic","includedCidrs":[],"#,
        r#""excludedCidrs":[],"routeDns":true,"dnsServers":["1.1.1.1"],"#,
        r#""allowLan":false,"mtu":1500}}"#
    );

    fn staged(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("veil-vpn-helper-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("staging dir");
        let path = dir.join("request.json");
        fs::write(&path, body).expect("write request");
        path
    }

    #[test]
    fn the_request_the_launch_approved_is_loaded() {
        let path = staged("good", REQUEST);
        let digest = crate::integrity::request_digest(REQUEST.as_bytes());
        let (config, dir) = load_config(&path, &digest).expect("load");
        assert_eq!(config.socks5_listen, "127.0.0.1:1080");
        assert_eq!(dir, path.parent().unwrap().canonicalize().unwrap());
    }

    #[test]
    fn a_request_swapped_after_the_prompt_is_refused() {
        // The digest is taken over what the host WROTE; the file then holds
        // something else by the time the elevated helper reads it.
        let digest = crate::integrity::request_digest(REQUEST.as_bytes());
        let path = staged("tampered", TAMPERED);
        let error = load_config(&path, &digest).expect_err("tampered request loaded");
        assert!(
            error.contains("does not match the approved launch"),
            "refused for the wrong reason: {error}"
        );
    }

    #[test]
    fn the_tampered_request_would_otherwise_have_parsed() {
        // Vacuity guard. If the swapped body were simply invalid JSON the test
        // above would pass on the parser, not on the digest.
        let value = serde_json::from_str::<HelperConfig>(TAMPERED).expect("tampered parses");
        assert_eq!(value.socks5_listen, "10.66.66.66:1080");
    }

    /// The DACL Windows actually stored on `path`, as SDDL.
    fn dacl_of(path: &Path) -> String {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; every unused out parameter is null.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(rc, 0, "GetNamedSecurityInfoW failed for {}", path.display());
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: the descriptor came back from the call above.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "could not render the DACL as SDDL");
        let mut len = 0usize;
        // SAFETY: the converter returns a NUL-terminated string.
        while unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units precede the terminator.
        let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: both allocations came from LocalAlloc.
        unsafe {
            LocalFree(text as *mut _);
            LocalFree(descriptor as *mut _);
        }
        out
    }

    #[test]
    fn the_status_directory_is_one_this_user_cannot_write() {
        // The point of the whole change, read back from Windows rather than
        // assumed: an ACL you have not asked for is an ACL you are guessing at.
        let session = std::env::temp_dir().join(format!(
            "xveil-vpn-acltest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = protected_status_dir(&session).expect("create the status dir");
        let sddl = dacl_of(&dir);
        let _ = fs::remove_dir(&dir);

        assert!(
            sddl.starts_with("D:P"),
            "the DACL is not protected, so it inherits whatever the parent \
             grants: {sddl}"
        );
        assert!(
            sddl.contains("(A;OICI;FA;;;SY)"),
            "SYSTEM lost full control: {sddl}"
        );
        assert!(
            sddl.contains("(A;OICI;FA;;;BA)"),
            "Administrators lost full control: {sddl}"
        );
        assert!(
            sddl.contains("(A;OICI;FR;;;BU)"),
            "Users cannot READ the status, so the unelevated host cannot poll \
             it: {sddl}"
        );
        assert!(
            !sddl.contains("FA;;;BU") && !sddl.contains("FW;;;BU"),
            "Users can WRITE the status — the forgery this move exists to \
             stop: {sddl}"
        );
    }

    #[test]
    fn a_status_directory_that_already_exists_is_refused() {
        // Nothing to squat on: the name is the session's, and a create that
        // would reuse an existing directory is an error rather than a silent
        // adoption of somebody else's ACL.
        let session = std::env::temp_dir().join(format!(
            "xveil-vpn-acltest2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = protected_status_dir(&session).expect("first create");
        let again = protected_status_dir(&session);
        let _ = fs::remove_dir(&dir);
        assert!(
            again.is_err(),
            "a second run adopted the first run's directory"
        );
    }

    /// Open the control pipe as a client would, and write `payload`.
    ///
    /// CREATE_ALWAYS on purpose: that is the disposition `dart:io` uses for
    /// `FileMode.write`, and the host is Dart. Measured on a Windows 11 ARM64
    /// stand — it opens a pipe client, and so does OPEN_ALWAYS.
    fn connect_and_write(name: &str, payload: &[u8]) {
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        use windows_sys::Win32::Storage::FileSystem::{
            CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, WriteFile,
        };
        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated for the call.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                0,
                ptr::null(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "the client could not connect");
        let mut wrote = 0u32;
        // SAFETY: the buffer outlives the call and its length is exact.
        unsafe {
            WriteFile(
                handle,
                payload.as_ptr(),
                payload.len() as u32,
                &mut wrote,
                ptr::null_mut(),
            );
            CloseHandle(handle);
        }
    }

    fn probe_pipe(tag: &str) -> (String, Handle) {
        let session = std::env::temp_dir().join(format!(
            "xveil-vpn-pipe-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let name = control_pipe_name(&session).expect("a pipe name");
        let pipe = create_control_pipe(&name).expect("the pipe");
        (name, pipe)
    }

    #[test]
    fn the_host_can_stop_the_tunnel_over_the_pipe() {
        let (name, pipe) = probe_pipe("ok");
        let client = std::thread::spawn(move || connect_and_write(&name, b"stop"));
        let stopped = stop_requested_by_host(pipe.0, std::process::id());
        client.join().unwrap();
        assert!(stopped, "the host's stop did not arrive");
    }

    #[test]
    fn a_stop_from_any_other_process_is_refused() {
        // The whole reason this is a pipe and not a file. The DACL cannot tell
        // two processes of one user apart — same user, same access — so the
        // check is WHO connected, and only the host this run was launched for
        // is accepted (report5 R5-X-03).
        let (name, pipe) = probe_pipe("wrongpid");
        let client = std::thread::spawn(move || connect_and_write(&name, b"stop"));
        // Our own pid, deliberately not the one the helper was told to trust.
        let impostor = std::process::id().wrapping_add(1);
        let stopped = stop_requested_by_host(pipe.0, impostor);
        client.join().unwrap();
        assert!(
            !stopped,
            "a stop from a process that is not the host was taken"
        );
    }

    #[test]
    fn a_connection_that_says_something_else_is_not_a_stop() {
        let (name, pipe) = probe_pipe("garbage");
        let client = std::thread::spawn(move || connect_and_write(&name, b"go"));
        let stopped = stop_requested_by_host(pipe.0, std::process::id());
        client.join().unwrap();
        assert!(!stopped);
    }

    #[test]
    fn the_pipe_is_named_after_its_session_and_nothing_else() {
        // Two runs must not share a control pipe: the name is the session's,
        // which is random per launch.
        let a = control_pipe_name(Path::new(r"C:\Temp\xveil-vpn-aaa")).unwrap();
        let b = control_pipe_name(Path::new(r"C:\Temp\xveil-vpn-bbb")).unwrap();
        assert_ne!(a, b);
        assert!(a.ends_with("xveil-vpn-aaa"), "{a}");
        assert!(a.starts_with(r"\\.\pipe\"), "{a}");
    }

    #[test]
    fn an_absent_or_short_expectation_is_not_a_way_to_skip_the_check() {
        let path = staged("nodigest", REQUEST);
        for expected in ["", "0", &"a".repeat(63)] {
            assert!(
                load_config(&path, expected).is_err(),
                "{expected:?} was accepted as an expectation"
            );
        }
    }
}
