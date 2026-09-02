use crate::Args;
use std::os::raw::{c_char, c_int, c_ushort};

/// # Safety
/// Run the tun2proxy component with command line arguments
/// Parameters:
/// - cli_args: The command line arguments,
///   e.g. `tun2proxy-bin --setup --proxy socks5://127.0.0.1:1080 --bypass 98.76.54.0/24 --dns over-tcp --verbosity trace`
/// - tun_mtu: The MTU of the TUN device, e.g. 1500
/// - packet_information: Whether exists packet information in packet from TUN device
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_run_with_cli_args(cli_args: *const c_char, tun_mtu: c_ushort, packet_information: bool) -> c_int {
    // A C caller can pass NULL, and CStr::from_ptr on NULL is undefined
    // behaviour rather than an error you get to return.
    if cli_args.is_null() {
        log::error!("cli_args is NULL");
        return -7;
    }
    let Ok(cli_args) = unsafe { std::ffi::CStr::from_ptr(cli_args) }.to_str() else {
        log::error!("Failed to convert CLI arguments to string");
        return -5;
    };
    let Some(args) = shlex::split(cli_args) else {
        log::error!("Failed to split CLI arguments");
        return -6;
    };
    // try_parse_from, not parse_from: parse_from writes to stderr and calls
    // process::exit on anything it dislikes, including --help. That turns one
    // bad argument string from a C caller into a dead host process.
    let args = match <Args as ::clap::Parser>::try_parse_from(args) {
        Ok(args) => args,
        Err(err) => {
            log::error!("Failed to parse CLI arguments: {err}");
            return -8;
        }
    };
    general_run_for_api(args, tun_mtu, packet_information)
}

/// The running tunnel's cancellation token, and WHICH run installed it.
///
/// The generation is what makes the slot ownable. Without it the teardown at
/// the end of a run cleared whatever was in here, and there is a window where
/// that is not its own: a run finishes, a stop takes and cancels its token,
/// a NEW run starts and installs the next one — and then the first run's
/// teardown, resuming, removes it. The second tunnel is then running with
/// nothing to stop it, and `tun2proxy_stop` answers -1 for the life of the
/// process (report20 V18-M7).
static TUN_QUIT: std::sync::Mutex<Option<(u64, tokio_util::sync::CancellationToken)>> = std::sync::Mutex::new(None);

static NEXT_RUN_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Take the run slot, or `None` when a tunnel is already in it.
fn claim_run_slot() -> Option<(u64, tokio_util::sync::CancellationToken)> {
    let mut lock = TUN_QUIT.lock().ok()?;
    if lock.is_some() {
        return None;
    }
    let generation = NEXT_RUN_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let token = tokio_util::sync::CancellationToken::new();
    *lock = Some((generation, token.clone()));
    Some((generation, token))
}

/// Give the slot back — only if it still holds THIS run.
///
/// Returns whether it did, which is the difference between "I cleaned up after
/// myself" and "somebody else's tunnel is in there now and I nearly unhooked
/// its stop".
fn release_run_slot(generation: u64) -> bool {
    let Ok(mut lock) = TUN_QUIT.lock() else {
        return false;
    };
    if lock.as_ref().is_some_and(|(g, _)| *g == generation) {
        lock.take();
        return true;
    }
    false
}

pub(crate) fn tun2proxy_stop_internal() -> c_int {
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if let Some((_, shutdown_token)) = lock.take() {
            shutdown_token.cancel();
            return 0;
        }
    }
    -1
}

pub fn general_run_for_api(args: Args, tun_mtu: u16, packet_information: bool) -> c_int {
    log::set_max_level(args.verbosity.into());
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::debug!("set logger error: {err}");
    }

    let Some((generation, shutdown_token)) = claim_run_slot() else {
        log::error!("tun2proxy already started, or its quit token could not be locked");
        return -1;
    };

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        log::error!("failed to create tokio runtime with");
        return -3;
    };
    let args_clone = args.clone();
    let res = rt.block_on(general_run_async(args_clone, tun_mtu, packet_information, shutdown_token));

    // Upstream spawned a detached thread here that slept FORCE_EXIT_TIMEOUT and
    // then called std::process::exit(-1) unconditionally - on every call,
    // including the ones that returned Ok. Anything embedding this library died
    // two seconds after the tunnel stopped, with an exit code it never chose and
    // no chance to run a destructor. A library does not get to end its host.
    //
    // What that thread was reaching for is real: dropping a tokio runtime blocks
    // until its blocking tasks finish, and one that never finishes would hang
    // here instead. shutdown_timeout is the bounded form - it waits, then
    // returns and leaks whatever refused to stop. The caller stays alive either
    // way and decides for itself what to do about it.
    rt.shutdown_timeout(crate::FORCE_EXIT_TIMEOUT);

    let res = match res {
        Ok(sessions) => {
            log::debug!("tun2proxy exited normally, current session count: {sessions}");
            0
        }
        Err(e) => {
            log::error!("failed to run tun2proxy with error: {e:?}");
            -4
        }
    };

    // Only THIS run's slot. Clearing whatever is there unhooks the stop of a
    // tunnel that started while this one was on its way out.
    if !release_run_slot(generation) {
        log::debug!("tun2proxy run {generation} finished after its slot was taken over");
    }

    res
}

/// Run the tun2proxy component with some arguments.
pub async fn general_run_async(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> std::io::Result<usize> {
    let mut tun_config = tun::Configuration::default();

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        use tproxy_config::{TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
        tun_config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(tun_mtu).up();
        tun_config.destination(TUN_GATEWAY);
    }

    #[cfg(unix)]
    if let Some(fd) = args.tun_fd {
        tun_config.raw_fd(fd);
        if let Some(v) = args.close_fd_on_drop {
            tun_config.close_fd_on_drop(v);
        };
    } else if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }
    #[cfg(windows)]
    if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|cfg| {
        #[allow(deprecated)]
        cfg.packet_information(true);
        cfg.ensure_root_privileges(args.setup);
    });

    #[cfg(target_os = "windows")]
    tun_config.platform_config(|cfg| {
        cfg.device_guid(12324323423423434234_u128);
    });

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    tun_config.platform_config(|cfg| {
        cfg.packet_information(_packet_information);
    });

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[allow(unused_variables)]
    let mut tproxy_args = tproxy_config::TproxyArgs::new()
        .tun_dns(args.dns_addr)
        .proxy_addr(args.proxy.addr)
        .bypass_ips(&args.bypass)
        .ipv6_default_route(args.ipv6_enabled);

    let device = tun::create_as_async(&tun_config)?;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if let Ok(tun_name) = tun::AbstractDevice::tun_name(&*device) {
        // Above line is equivalent to: `use tun::AbstractDevice; if let Ok(tun_name) = device.tun_name() {`
        tproxy_args = tproxy_args.tun_name(&tun_name);
    }

    // TproxyState implements the Drop trait to restore network configuration,
    // so we need to assign it to a variable, even if it is not used.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let mut restore: Option<tproxy_config::TproxyState> = None;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if args.setup {
        restore = Some(tproxy_config::tproxy_setup(&tproxy_args).await?);
    }

    #[cfg(target_os = "linux")]
    {
        let mut admin_command_args = args.admin_command.iter();
        if let Some(command) = admin_command_args.next() {
            let child = tokio::process::Command::new(command)
                .args(admin_command_args)
                .kill_on_drop(true)
                .spawn();

            match child {
                Err(err) => {
                    log::warn!("Failed to start admin process: {err}");
                }
                Ok(mut child) => {
                    tokio::spawn(async move {
                        if let Err(err) = child.wait().await {
                            log::warn!("Admin process terminated: {err}");
                        }
                    });
                }
            };
        }
    }

    let join_handle = tokio::spawn(crate::run(device, tun_mtu, args.clone(), shutdown_token.clone()));

    match join_handle.await? {
        Ok(sessions) => {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            tproxy_config::tproxy_remove(restore).await?;

            let max_sessions = args.max_sessions;
            if args.exit_on_fatal_error && sessions >= max_sessions {
                let info = format!("Forced exit due to max sessions reached ({sessions}/{max_sessions})");
                return Err(std::io::Error::other(info));
            }
            Ok(sessions)
        }
        Err(err) => Err(std::io::Error::from(err)),
    }
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_stop() -> c_int {
    tun2proxy_stop_internal()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bad input to the C entry point must come back as a return code, not as
    /// a dead host process.
    ///
    /// This runs the assertion in a child on purpose. The defect it guards
    /// against is unobservable in-process: `clap::parse_from` calls
    /// `process::exit`, so before the fix this test would have taken the whole
    /// test runner down with it and reported nothing at all - the failure and
    /// the thing that reports failures were the same process.
    #[test]
    fn bad_cli_args_return_instead_of_exiting_the_host() {
        const MARKER: &str = "HOST-STILL-ALIVE";
        const CHILD_ENV: &str = "TUN2PROXY_HOST_EXIT_CHILD";

        if std::env::var(CHILD_ENV).is_ok() {
            let bad = std::ffi::CString::new("tun2proxy --definitely-not-a-flag").unwrap();
            let rc = unsafe { tun2proxy_run_with_cli_args(bad.as_ptr(), 1500, false) };
            assert_eq!(rc, -8, "unparseable arguments should be reported, not fatal");

            let nul = unsafe { tun2proxy_run_with_cli_args(std::ptr::null(), 1500, false) };
            assert_eq!(nul, -7, "a NULL argument string should be refused, not dereferenced");

            println!("{MARKER}");
            return;
        }

        // --exact wants the full test path, and hardcoding it means the filter
        // silently matches nothing the day this module moves - the child then
        // runs 0 tests and reports success, which looks exactly like the child
        // dying. Derive it instead; module_path! carries the crate name, which
        // the test filter does not use.
        let module = module_path!();
        let filter = format!(
            "{}::bad_cli_args_return_instead_of_exiting_the_host",
            module.split_once("::").map(|(_, rest)| rest).unwrap_or(module)
        );

        let exe = std::env::current_exe().expect("test executable path");
        let out = std::process::Command::new(exe)
            .args([filter.as_str(), "--exact", "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("re-running this test as a child should work");

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(MARKER),
            "the child never got past the call; status {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(test)]
mod run_slot_tests {
    use super::*;

    /// report20 V18-M7: a finished run gives back ITS OWN slot, not whatever
    /// is in it.
    ///
    /// The teardown at the end of a run cleared the slot unconditionally, and
    /// there is a window where what it holds is not that run's: the run
    /// finishes, a stop takes and cancels its token, a NEW run starts and
    /// installs the next one — and the first run's teardown, resuming, removes
    /// it. The second tunnel is then running with nothing able to stop it, and
    /// `tun2proxy_stop` answers -1 for the rest of the process.
    #[test]
    fn a_finished_run_does_not_unhook_the_one_that_replaced_it() {
        // Run A takes the slot.
        let (gen_a, token_a) = claim_run_slot().expect("the slot is free");
        assert!(claim_run_slot().is_none(), "premise: one tunnel at a time");

        // A stop takes and cancels it — the slot is free again.
        assert_eq!(tun2proxy_stop_internal(), 0);
        assert!(token_a.is_cancelled());

        // Run B starts in the window before A's teardown runs.
        let (gen_b, token_b) = claim_run_slot().expect("the slot was freed by the stop");
        assert_ne!(gen_a, gen_b);

        // A's teardown finally runs. It must not touch B.
        assert!(!release_run_slot(gen_a), "run A reported clearing a slot that was not its own");

        // B is still stoppable, which is the whole of what was lost.
        assert_eq!(
            tun2proxy_stop_internal(),
            0,
            "the running tunnel has nothing to stop it: its token was removed \
             by the teardown of a run that had already ended"
        );
        assert!(token_b.is_cancelled());

        // Vacuity: a run that IS the current one does give its slot back, or
        // the slot would never be released at all.
        let (gen_c, _token_c) = claim_run_slot().expect("free again");
        assert!(release_run_slot(gen_c), "the owner could not release its own");
        assert!(claim_run_slot().is_some(), "the slot was not actually freed");
        assert_eq!(tun2proxy_stop_internal(), 0);
    }
}
