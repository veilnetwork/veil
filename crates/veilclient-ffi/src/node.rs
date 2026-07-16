//! Embedded node-runtime FFI (`node-embedded` feature).
//!
//! Runs a full veil node IN-PROCESS on a dedicated OS thread with its own
//! tokio runtime, so hosts that cannot spawn a subprocess (iOS, sandboxed
//! desktop) still get a node. The node serves its IPC socket from the config;
//! the existing `veil_connect` client then talks to it in-process.
//!
//! Readiness is intentionally the caller's responsibility: after `start`,
//! probe the IPC socket named in the config (or sent on apply-config), then
//! `veil_connect` to it. Keeping start non-blocking avoids the FFI guessing
//! when "ready" means.

use std::ffi::{CString, c_char, c_int};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use libc::size_t;
use tokio::sync::watch;

/// Minimal `log` -> stderr bridge for non-Android hosts. The embedded node's
/// runtime emits some diagnostics through the `log` crate (e.g. the onion-stream
/// `relay-pick` line), but on desktop nothing consumes `log`, so those vanish
/// (only the node's own tracing logger reaches stderr). Bridge them — non-
/// panicking: a failed stderr write is swallowed, never aborts (see the FFI
/// `diag` crash). Android already routes `log` to logcat via `android_logger`.
#[cfg(not(target_os = "android"))]
struct StderrLogBridge;

#[cfg(not(target_os = "android"))]
impl log::Log for StderrLogBridge {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr(),
                "[{} {}] {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }
    fn flush(&self) {}
}

/// Opaque handle to a running embedded node.
pub struct VeilNode {
    shutdown: Mutex<Option<watch::Sender<bool>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    /// Admin socket path — set when the node was started in deferred mode. This
    /// is the channel `veil_node_apply_config` uses to promote the ephemeral
    /// deferred node to its real (host-supplied) identity. `None` for nodes
    /// started from a config file (their admin socket lives in that config).
    admin_socket: Option<PathBuf>,
}

/// Write an owned error string into `*err_out` (freed by `veil_free_string`).
unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe { *err_out = c.into_raw() };
}

/// Provision a fresh node identity IN-PROCESS — generate an Ed25519 keypair and
/// mine its proof-of-work nonce — and return a ready-to-use config (TOML)
/// carrying that identity, WITHOUT writing anything to disk. The host stores the
/// returned bytes inside its own (deniable) container, so nothing
/// identity-bearing (private key, node_id) ever touches the filesystem. This is
/// the in-process replacement for `veil-cli config init` on mobile / sandboxed
/// hosts.
///
/// `difficulty` is the PoW difficulty in leading zero bits; pass `0` for the
/// canonical default. Mining runs synchronously on the calling thread (it can
/// take a while), so call this off the host's UI thread.
///
/// Returns a newly allocated C string (free it with `veil_free_string`) on
/// success, or NULL with `*err_out` set on failure.
///
/// # Safety
/// `err_out` (if non-null) must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_config_init(
    difficulty: u32,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    use veil_cfg::identity_ops::{IdentityPowParams, IdentityProvisionParams, IdentityUseCases};

    let defaults = IdentityProvisionParams::default();
    let pow = if difficulty == 0 {
        IdentityPowParams::default()
    } else {
        IdentityPowParams {
            difficulty,
            ..IdentityPowParams::default()
        }
    };
    let identity = match IdentityUseCases::new(pow).provision(defaults.algo, None) {
        Ok(id) => id,
        Err(e) => {
            unsafe { set_err(err_out, &format!("identity provisioning failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    let config = veil_cfg::Config {
        identity: Some(identity),
        ..veil_cfg::Config::default()
    };
    let toml = match veil_cfg::render_config_to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            unsafe { set_err(err_out, &format!("config render failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    match CString::new(toml) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            unsafe { set_err(err_out, "rendered config contained a NUL byte") };
            std::ptr::null_mut()
        }
    }
}

/// Like `veil_config_init`, but the Ed25519 identity is DERIVED FROM A MASTER
/// PHRASE instead of random (onboarding-phrase epic P2): phrase → master seed
/// (checksum verified) → the SAME HKDF the sovereign restore uses
/// (`veil_crypto::identity::derive_master_sk_ed25519`) → keypair; only the
/// anti-sybil nonce is searched. `node_id` depends only on the public key, so
/// the identity is deterministic in the phrase — a later disaster-recovery
/// restore lands on the SAME node_id — while the nonce is simply re-mined.
///
/// The caller's `(phrase, phrase_len)` buffer is overwritten with `0` before
/// returning on EVERY path (same contract as the validate/restore zeroize
/// variants); the decoded seed and derived secret zeroize on drop. Returns
/// the rendered config TOML (free with `veil_free_string`), or NULL with
/// `err_out` set. `difficulty` 0 = canonical.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_config_init_from_phrase_zeroize(
    phrase: *mut u8,
    phrase_len: size_t,
    difficulty: u32,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    use veil_cfg::identity_ops::{IdentityPowParams, IdentityUseCases};

    if phrase.is_null() {
        unsafe { set_err(err_out, "phrase is null") };
        return std::ptr::null_mut();
    }
    if phrase_len > 4096 {
        unsafe { set_err(err_out, "phrase too long (>4 KiB)") };
        return std::ptr::null_mut();
    }
    // Copy into an owned zeroizing buffer, then scrub the caller's bytes
    // immediately — the plaintext window collapses to this call regardless
    // of which error path is taken below.
    let owned =
        zeroize::Zeroizing::new(unsafe { std::slice::from_raw_parts(phrase, phrase_len) }.to_vec());
    unsafe { std::ptr::write_bytes(phrase, 0, phrase_len) };
    let phrase_str = match std::str::from_utf8(&owned) {
        Ok(s) => s,
        Err(_) => {
            unsafe { set_err(err_out, "phrase is not valid UTF-8") };
            return std::ptr::null_mut();
        }
    };
    let seed = match veil_identity::master_seed::decode_master_seed_from_phrase(phrase_str) {
        Ok(s) => s,
        Err(e) => {
            unsafe { set_err(err_out, &format!("phrase decode failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    let sk_seed = veil_crypto::identity::derive_master_sk_ed25519(&seed);
    let pow = if difficulty == 0 {
        IdentityPowParams::default()
    } else {
        IdentityPowParams {
            difficulty,
            ..IdentityPowParams::default()
        }
    };
    let identity = match IdentityUseCases::new(pow).provision_ed25519_from_secret(&sk_seed, None) {
        Ok(id) => id,
        Err(e) => {
            unsafe { set_err(err_out, &format!("identity provisioning failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    let config = veil_cfg::Config {
        identity: Some(identity),
        ..veil_cfg::Config::default()
    };
    let toml = match veil_cfg::render_config_to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            unsafe { set_err(err_out, &format!("config render failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    match CString::new(toml) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            unsafe { set_err(err_out, "rendered config contained a NUL byte") };
            std::ptr::null_mut()
        }
    }
}

/// Read a `(ptr, len)` UTF-8 argument into an owned `String`, or set `*err_out`
/// and return `None`. `what` names the argument for the error message.
unsafe fn read_arg(
    ptr: *const u8,
    len: size_t,
    what: &str,
    err_out: *mut *mut c_char,
) -> Option<String> {
    if ptr.is_null() {
        unsafe { set_err(err_out, &format!("{what} is null")) };
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    match std::str::from_utf8(bytes) {
        Ok(s) => Some(s.to_owned()),
        Err(_) => {
            unsafe { set_err(err_out, &format!("{what} is not valid UTF-8")) };
            None
        }
    }
}

/// Compose a full, bootable node config by combining a stored identity (the
/// config TOML from `veil_config_init`, kept in the host's deniable container)
/// with EPHEMERAL runtime endpoints chosen per launch: `listen_transport` (e.g.
/// `tcp://127.0.0.1:9931`), `ipc_socket`, and `admin_socket` (filesystem paths,
/// wrapped as `unix://`). None of these endpoints are identity-bearing, so they
/// are not stored — only the identity is. Returns the merged config as TOML
/// (free with `veil_free_string`), or NULL with `*err_out` set.
///
/// # Safety
/// Each `*_ptr` must point to its `*_len` readable bytes; `err_out` (if non-null)
/// must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn veil_config_compose(
    identity_toml_ptr: *const u8,
    identity_toml_len: size_t,
    listen_transport_ptr: *const u8,
    listen_transport_len: size_t,
    ipc_socket_ptr: *const u8,
    ipc_socket_len: size_t,
    admin_socket_ptr: *const u8,
    admin_socket_len: size_t,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let identity_toml = match unsafe {
        read_arg(
            identity_toml_ptr,
            identity_toml_len,
            "identity_toml",
            err_out,
        )
    } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let listen = match unsafe {
        read_arg(
            listen_transport_ptr,
            listen_transport_len,
            "listen_transport",
            err_out,
        )
    } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let ipc = match unsafe { read_arg(ipc_socket_ptr, ipc_socket_len, "ipc_socket", err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let admin =
        match unsafe { read_arg(admin_socket_ptr, admin_socket_len, "admin_socket", err_out) } {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };

    // Build the runtime endpoints as a TOML template so veil-cfg parses them
    // into the right structs (no hand-constructed ListenConfig), then graft on
    // the stored identity.
    let ipc_endpoint = if ipc.contains("://") {
        ipc
    } else {
        format!("unix://{ipc}")
    };
    let admin_endpoint = if admin.contains("://") {
        admin
    } else {
        format!("unix://{admin}")
    };
    let template = format!(
        "[[listen]]\nid = \"0x00000001\"\ntransport = \"{listen}\"\n\n\
         [ipc]\nenabled = true\nsocket_uri = \"{ipc_endpoint}\"\n\n\
         [global]\nadmin_socket = \"{admin_endpoint}\"\n"
    );
    let mut config = match veil_cfg::parse_toml_str(&template) {
        Ok(c) => c,
        Err(e) => {
            unsafe { set_err(err_out, &format!("runtime template parse failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    let identity_config = match veil_cfg::parse_toml_str(&identity_toml) {
        Ok(c) => c,
        Err(e) => {
            unsafe { set_err(err_out, &format!("identity parse failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    if identity_config.identity.is_none() {
        unsafe { set_err(err_out, "identity_toml carries no [Identity]") };
        return std::ptr::null_mut();
    }
    config.identity = identity_config.identity;
    // The embedded deniable node is ephemeral and keeps NOTHING on disk: the
    // host app holds all state in its encrypted container, so writing veil's
    // snapshot files (DHT values, RTT/Vivaldi/gateway tables, peer pubkeys,
    // discovered-peer cache) to the working dir would be a deniability leak and
    // the source of the `dht.values.persist.flush_err` warning. Apply-config is
    // a reload that re-spawns the persist tasks from THIS config, so the switch
    // must be set here too (not only in the deferred stub).
    config.persist_enabled = false;

    let toml = match veil_cfg::render_config_to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            unsafe { set_err(err_out, &format!("config render failed: {e}")) };
            return std::ptr::null_mut();
        }
    };
    match CString::new(toml) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            unsafe { set_err(err_out, "rendered config contained a NUL byte") };
            std::ptr::null_mut()
        }
    }
}

/// Start an embedded node from a config file at `config_path` (`(ptr,len)`,
/// UTF-8). Non-blocking. Returns an opaque handle, or null with `*err_out` set
/// (free it with `veil_free_string`).
///
/// # Safety
/// `config_path_ptr` must point to `config_path_len` readable bytes; `err_out`
/// (if non-null) must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_node_start(
    config_path_ptr: *const u8,
    config_path_len: size_t,
    err_out: *mut *mut c_char,
) -> *mut VeilNode {
    if config_path_ptr.is_null() {
        unsafe { set_err(err_out, "config_path is null") };
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(config_path_ptr, config_path_len) };
    let path = match std::str::from_utf8(bytes) {
        Ok(s) => PathBuf::from(s),
        Err(_) => {
            unsafe { set_err(err_out, "config_path is not valid UTF-8") };
            return std::ptr::null_mut();
        }
    };
    // Fail fast on an unreadable/invalid config so the caller gets a clean
    // error rather than a handle to a node that exits immediately.
    if let Err(e) = veil_cfg::load_config(&path) {
        unsafe { set_err(err_out, &format!("config load failed: {e}")) };
        return std::ptr::null_mut();
    }
    // Config-file mode carries its own `[anonymity]` in that file — the stub
    // `anonymous` flag only applies to the deferred (config-less) boot.
    start_thread(Some(path), None, None, false, err_out)
}

/// Start an embedded node in deferred-init mode: it boots under an ephemeral
/// throwaway identity, binds ONLY the admin endpoint at `admin_socket` (`(ptr,
/// len)`, UTF-8 Unix path or authenticated loopback-TCP URI), and waits. Promote it to its real identity by
/// pushing a config with `veil_node_apply_config` — so the real private key
/// never has to be written to a config file on disk.
///
/// Pick an ephemeral, identity-free endpoint for `admin_socket` (e.g. a path
/// under a per-launch temp dir, or `tcp://127.0.0.1:0?runtime_dir=...`).
/// Non-blocking; returns an opaque handle or null + err.
///
/// `anonymous` arms `[anonymity]` in the stub boot config so the node is
/// actually onion-reachable once its real identity is applied. It MUST be set
/// here (at boot) rather than via `veil_node_apply_config`: anonymity is pinned
/// at startup and the later apply-config (a reload) does not re-apply it. The
/// published onion descriptor is sealed against the live identity, so it
/// resolves to the real identity once `veil_node_apply_config` promotes it.
///
/// # Safety
/// `admin_socket_ptr` must point to `admin_socket_len` readable bytes; `err_out`
/// (if non-null) must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_node_start_deferred(
    admin_socket_ptr: *const u8,
    admin_socket_len: size_t,
    anonymous: bool,
    err_out: *mut *mut c_char,
) -> *mut VeilNode {
    if admin_socket_ptr.is_null() {
        unsafe { set_err(err_out, "admin_socket is null") };
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(admin_socket_ptr, admin_socket_len) };
    let endpoint = match std::str::from_utf8(bytes) {
        Ok(s) if s.contains("://") => s.to_owned(),
        Ok(s) => format!("unix://{s}"),
        Err(_) => {
            unsafe { set_err(err_out, "admin_socket is not valid UTF-8") };
            return std::ptr::null_mut();
        }
    };
    let anchor = if let Some(path) = endpoint.strip_prefix("unix://") {
        PathBuf::from(path)
    } else if endpoint.starts_with("tcp://") {
        let runtime_dir = endpoint
            .split_once('?')
            .and_then(|(_, query)| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("runtime_dir="))
            })
            .filter(|value| !value.is_empty());
        let Some(runtime_dir) = runtime_dir else {
            unsafe { set_err(err_out, "TCP admin endpoint requires runtime_dir") };
            return std::ptr::null_mut();
        };
        PathBuf::from(runtime_dir).join("admin.anchor")
    } else {
        unsafe { set_err(err_out, "admin_socket must use unix:// or tcp://") };
        return std::ptr::null_mut();
    };
    // Android: `std::env::temp_dir()` defaults to /data/local/tmp, which a normal
    // app CANNOT write — the deferred boot's `tempfile` working dir then fails
    // with EACCES and the node thread exits before binding its admin socket, so
    // apply_config sees ENOENT forever. The admin socket lives in an app-writable
    // dir, so point TMPDIR (which temp_dir() honours) at its parent. This fixes
    // every temp_dir() user in the embedded node at once, not just the deferred
    // working dir.
    #[cfg(target_os = "android")]
    if let Some(parent) = anchor.parent() {
        // Safety: set once at boot, before the node thread (the env reader) is
        // spawned, so there is no concurrent env access.
        unsafe { std::env::set_var("TMPDIR", parent) };
    }
    start_thread(None, Some(endpoint), Some(anchor), anonymous, err_out)
}

fn start_thread(
    config: Option<PathBuf>,
    admin_endpoint: Option<String>,
    admin_socket: Option<PathBuf>,
    anonymous: bool,
    err_out: *mut *mut c_char,
) -> *mut VeilNode {
    let (tx, mut rx) = watch::channel(false);
    let mut shutdown_deadline = rx.clone();
    let thread_admin_endpoint = admin_endpoint;
    let spawn = std::thread::Builder::new()
        .name("veil-node".into())
        .spawn(move || {
            // Android: bridge the node's `log` output to logcat (tag `veilnode`)
            // once — Rust stderr is invisible there, so without this the embedded
            // node is undebuggable on-device. No-op on other platforms.
            #[cfg(target_os = "android")]
            {
                use std::sync::Once;
                static INIT: Once = Once::new();
                INIT.call_once(|| {
                    android_logger::init_once(
                        android_logger::Config::default()
                            .with_max_level(log::LevelFilter::Info)
                            .with_tag("veilnode"),
                    );
                });
            }
            // Desktop/iOS: bridge `log` -> stderr once so the runtime's `log`
            // diagnostics (onion-stream relay-pick &c.) are visible here too.
            #[cfg(not(target_os = "android"))]
            {
                use std::sync::Once;
                static INIT: Once = Once::new();
                static BRIDGE: StderrLogBridge = StderrLogBridge;
                INIT.call_once(|| {
                    if log::set_logger(&BRIDGE).is_ok() {
                        log::set_max_level(log::LevelFilter::Info);
                    }
                });
            }
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    crate::ffi_diag(&format!("veil_node: tokio runtime build failed: {e}"));
                    #[cfg(target_os = "android")]
                    log::error!("veil_node: tokio runtime build failed: {e}");
                    return;
                }
            };
            let shutdown = async move {
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
            };
            let foreground = async move {
                match config {
                    Some(p) => {
                        veil_node_runtime::admin::run_foreground_with_shutdown(p, true, shutdown)
                            .await
                    }
                    None => {
                        veil_node_runtime::admin::run_foreground_deferred_with_shutdown(
                            thread_admin_endpoint,
                            anonymous,
                            shutdown,
                        )
                        .await
                    }
                }
            };
            let result = rt.block_on(async move {
                tokio::pin!(foreground);
                tokio::select! {
                    result = &mut foreground => Some(result),
                    _ = async move {
                        while !*shutdown_deadline.borrow() {
                            if shutdown_deadline.changed().await.is_err() {
                                return;
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } => None,
                }
            });
            if let Some(Err(e)) = result {
                crate::ffi_diag(&format!("veil_node: runtime exited with error: {e}"));
                #[cfg(target_os = "android")]
                log::error!("veil_node: runtime exited with error: {e}");
            } else if result.is_none() {
                crate::ffi_diag(
                    "veil_node: graceful shutdown exceeded 5s; cancelling residual tasks",
                );
            }
            // `NodeRuntime::stop` owns and joins its tracked services, but
            // defensive/background work spawned below the overlay stack may
            // still be alive (for example an in-flight onion resolve). A plain
            // Runtime drop waits forever for any blocking task that outlives
            // the node, which makes the synchronous `veil_node_stop`/thread
            // join hang the embedding process during shutdown. Cancel all
            // remaining async work and bound the wait for blocking work at the
            // outermost owner. The normal graceful path above still runs first.
            rt.shutdown_timeout(Duration::from_secs(5));
        });

    match spawn {
        Ok(thread) => Box::into_raw(Box::new(VeilNode {
            shutdown: Mutex::new(Some(tx)),
            thread: Mutex::new(Some(thread)),
            admin_socket,
        })),
        Err(e) => {
            unsafe { set_err(err_out, &format!("failed to spawn node thread: {e}")) };
            std::ptr::null_mut()
        }
    }
}

/// Promote a deferred-init node to its real identity by applying `config_toml`
/// (`(ptr, len)`, UTF-8 — e.g. the bytes returned by `veil_config_init` and
/// kept in the host's deniable storage) over the node's admin socket, IN MEMORY
/// (`persist = false`, so nothing is written to disk). Retries briefly while the
/// deferred node finishes binding its admin socket.
///
/// The node must have been started with `veil_node_start_deferred`. Returns 0 on
/// success, -1 on failure with `*err_out` set (free it with `veil_free_string`).
///
/// # Safety
/// `node` must be a live handle from `veil_node_start_deferred`; `config_ptr`
/// must point to `config_len` readable bytes; `err_out` (if non-null) must be a
/// writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_node_apply_config(
    node: *const VeilNode,
    config_ptr: *const u8,
    config_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if node.is_null() {
        unsafe { set_err(err_out, "node is null") };
        return -1;
    }
    let node = unsafe { &*node };
    let admin_socket = match &node.admin_socket {
        Some(p) => p.clone(),
        None => {
            unsafe {
                set_err(
                    err_out,
                    "node was not started in deferred mode (no admin socket to apply config to)",
                )
            };
            return -1;
        }
    };
    if config_ptr.is_null() {
        unsafe { set_err(err_out, "config is null") };
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len) };
    let toml_content = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            unsafe { set_err(err_out, "config is not valid UTF-8") };
            return -1;
        }
    };

    // A short-lived current-thread runtime drives the async admin client. The
    // deferred node may still be binding its admin socket, so retry-connect for
    // a few seconds before giving up.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            unsafe { set_err(err_out, &format!("apply_config runtime build failed: {e}")) };
            return -1;
        }
    };
    // A deferred node binds its admin socket only once its runtime is up. The
    // stub identity is a FIXED pre-mined constant (see
    // `build_stub_config_with_ephemeral_identity`, `lazy_mining = false`), so
    // there is NO per-boot PoW search — admin normally comes up within a second
    // or two (tokio runtime spin-up + socket bind). The first attempt fires
    // immediately and we only sleep AFTER a failed connect, so this returns the
    // instant admin is ready. The generous ceiling is purely a failsafe for a
    // node that never comes up at all (e.g. a port it can't bind).
    const APPLY_CONNECT_ATTEMPTS: usize = 900; // ~90 s @ 100 ms
    let outcome = rt.block_on(async {
        let mut last_err = String::from("admin socket never became ready");
        for _ in 0..APPLY_CONNECT_ATTEMPTS {
            let cmd = veil_node_runtime::admin::AdminCommand::ApplyConfig {
                toml_content: toml_content.clone(),
                persist: false,
            };
            match veil_node_runtime::admin::send_request(&admin_socket, cmd).await {
                Ok(resp) => {
                    return match resp.error {
                        Some(e) => Err(format!("apply-config rejected: {e}")),
                        None => Ok(()),
                    };
                }
                Err(e) => {
                    last_err = e.to_string();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err(last_err)
    });
    match outcome {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_err(err_out, &e) };
            -1
        }
    }
}

/// Stop the embedded node: trigger graceful shutdown and join its thread.
/// Consumes the handle.
///
/// # Safety
/// `node` must be a handle returned by `veil_node_start*` and not yet stopped.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_node_stop(node: *mut VeilNode) {
    if node.is_null() {
        return;
    }
    let node = unsafe { Box::from_raw(node) };
    if let Some(tx) = veil_util::lock!(node.shutdown).take() {
        let _ = tx.send(true);
    }
    if let Some(thread) = veil_util::lock!(node.thread).take() {
        let _ = thread.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    /// Onboarding-phrase epic P2: the identity config is DETERMINISTIC in the
    /// phrase (same public_key + node_id across calls — a later restore lands
    /// on the same identity), the caller's phrase buffer is scrubbed, and a
    /// garbage phrase is rejected.
    #[test]
    fn config_init_from_phrase_is_deterministic_in_the_phrase() {
        let mut phrase_ptr: *mut c_char = std::ptr::null_mut();
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { crate::veil_generate_master_phrase(&mut phrase_ptr, &mut err) };
        assert_eq!(rc, crate::VEIL_OK);
        let phrase = unsafe { CStr::from_ptr(phrase_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { crate::veil_free_string(phrase_ptr) };

        fn init(phrase: &str) -> String {
            let mut buf = phrase.as_bytes().to_vec();
            let mut err: *mut c_char = std::ptr::null_mut();
            let toml_ptr = unsafe {
                veil_config_init_from_phrase_zeroize(buf.as_mut_ptr(), buf.len(), 1, &mut err)
            };
            assert!(!toml_ptr.is_null(), "init from phrase failed");
            assert!(
                buf.iter().all(|b| *b == 0),
                "caller phrase buffer must be scrubbed"
            );
            let s = unsafe { CStr::from_ptr(toml_ptr) }
                .to_str()
                .unwrap()
                .to_string();
            unsafe { crate::veil_free_string(toml_ptr) };
            s
        }
        fn field(toml: &str, key: &str) -> String {
            toml.lines()
                .find(|l| l.trim_start().starts_with(key))
                .unwrap_or_else(|| panic!("no {key} in config"))
                .trim()
                .to_string()
        }

        let a = init(&phrase);
        let b = init(&phrase);
        assert_eq!(field(&a, "public_key"), field(&b, "public_key"));
        assert_eq!(field(&a, "node_id"), field(&b, "node_id"));

        // Garbage phrase → NULL + error, buffer still scrubbed.
        let mut junk = b"not a phrase at all".to_vec();
        let mut err2: *mut c_char = std::ptr::null_mut();
        let p = unsafe {
            veil_config_init_from_phrase_zeroize(junk.as_mut_ptr(), junk.len(), 1, &mut err2)
        };
        assert!(p.is_null());
        assert!(!err2.is_null());
        assert!(junk.iter().all(|b| *b == 0));
        unsafe { crate::veil_free_string(err2) };
    }

    #[test]
    fn start_rejects_unreadable_config() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let path = b"/nonexistent/definitely/no/such/config.toml";
        let handle = unsafe { veil_node_start(path.as_ptr(), path.len(), &mut err) };
        assert!(
            handle.is_null(),
            "should not return a handle for a bad config"
        );
        assert!(!err.is_null(), "should set an error string");
        let msg = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        assert!(msg.contains("config load failed"), "got: {msg}");
        unsafe { crate::veil_free_string(err) };
    }

    #[test]
    fn start_rejects_null_path() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe { veil_node_start(std::ptr::null(), 0, &mut err) };
        assert!(handle.is_null());
        unsafe {
            if !err.is_null() {
                crate::veil_free_string(err);
            }
        }
    }

    #[test]
    fn config_init_mines_identity_in_memory() {
        let mut err: *mut c_char = std::ptr::null_mut();
        // Low difficulty so the test is fast — the default is intentionally slow.
        let out = unsafe { veil_config_init(8, &mut err) };
        assert!(!out.is_null(), "expected a config string");
        assert!(err.is_null(), "no error expected");
        let toml = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(out) };

        // The returned bytes are a parseable config carrying a usable identity —
        // and nothing was written to disk to produce it.
        let cfg = veil_cfg::parse_toml_str(&toml).expect("config parses back");
        let id = cfg.identity.expect("identity present");
        assert!(!id.private_key.is_empty(), "has a private key");
        assert!(!id.public_key.is_empty(), "has a public key");
        assert!(id.node_id.is_some(), "has a node_id");
    }

    #[test]
    fn config_compose_merges_identity_with_runtime() {
        // Mine an identity (the bytes a host stores in its container) ...
        let mut err: *mut c_char = std::ptr::null_mut();
        let id_out = unsafe { veil_config_init(8, &mut err) };
        assert!(!id_out.is_null());
        let identity_toml = unsafe { CStr::from_ptr(id_out) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(id_out) };

        // ... then compose a bootable config around it with ephemeral endpoints.
        let listen = b"tcp://127.0.0.1:9931";
        let ipc = b"/tmp/xveil-test-ipc.sock";
        let admin = b"/tmp/xveil-test-admin.sock";
        let out = unsafe {
            veil_config_compose(
                identity_toml.as_ptr(),
                identity_toml.len(),
                listen.as_ptr(),
                listen.len(),
                ipc.as_ptr(),
                ipc.len(),
                admin.as_ptr(),
                admin.len(),
                &mut err,
            )
        };
        assert!(!out.is_null(), "compose returned null");
        let full = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(out) };

        let cfg = veil_cfg::parse_toml_str(&full).expect("composed config parses");
        // Identity preserved...
        assert!(cfg.identity.is_some(), "identity merged in");
        // ...and the runtime endpoints are present so the node can actually run.
        assert_eq!(cfg.listen.len(), 1, "one listener");
        assert!(cfg.ipc.enabled, "ipc enabled");
        assert!(
            cfg.ipc
                .socket_uri
                .as_deref()
                .unwrap_or("")
                .contains("xveil-test-ipc.sock")
        );
        assert!(
            cfg.global
                .admin_socket
                .as_deref()
                .unwrap_or("")
                .contains("xveil-test-admin.sock")
        );
    }

    #[test]
    fn config_compose_preserves_authenticated_loopback_endpoints() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let id_out = unsafe { veil_config_init(8, &mut err) };
        assert!(!id_out.is_null());
        let identity_toml = unsafe { CStr::from_ptr(id_out) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(id_out) };

        let listen = b"tcp://127.0.0.1:9931";
        let ipc = b"tcp://127.0.0.1:0?runtime_dir=/tmp/xveil-ios";
        let admin = b"tcp://127.0.0.1:0?runtime_dir=/tmp/xveil-ios";
        let out = unsafe {
            veil_config_compose(
                identity_toml.as_ptr(),
                identity_toml.len(),
                listen.as_ptr(),
                listen.len(),
                ipc.as_ptr(),
                ipc.len(),
                admin.as_ptr(),
                admin.len(),
                &mut err,
            )
        };
        assert!(!out.is_null(), "compose returned null");
        let full = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(out) };

        let cfg = veil_cfg::parse_toml_str(&full).expect("composed config parses");
        assert_eq!(
            cfg.ipc.socket_uri.as_deref(),
            Some(std::str::from_utf8(ipc).unwrap())
        );
        assert_eq!(
            cfg.global.admin_socket.as_deref(),
            Some(std::str::from_utf8(admin).unwrap())
        );
    }

    #[test]
    fn apply_config_rejects_null_node() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let toml = b"[global]\n";
        let rc = unsafe {
            veil_node_apply_config(std::ptr::null(), toml.as_ptr(), toml.len(), &mut err)
        };
        assert_eq!(rc, -1);
        unsafe {
            if !err.is_null() {
                crate::veil_free_string(err);
            }
        }
    }

    #[test]
    fn apply_config_requires_a_deferred_node() {
        // A node with no admin socket (i.e. not started deferred) is rejected
        // immediately — no hang on admin-socket connect retries.
        let node = VeilNode {
            shutdown: Mutex::new(None),
            thread: Mutex::new(None),
            admin_socket: None,
        };
        let mut err: *mut c_char = std::ptr::null_mut();
        let toml = b"[global]\n";
        let rc = unsafe { veil_node_apply_config(&node, toml.as_ptr(), toml.len(), &mut err) };
        assert_eq!(rc, -1);
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        assert!(msg.contains("deferred"), "got: {msg}");
        unsafe { crate::veil_free_string(err) };
    }

    // Reproduces the xVeil deniable-boot flow end to end: provision an identity,
    // compose a full config around ephemeral sockets, start a deferred node, and
    // promote it with apply-config. Heavy (boots a real node) — run explicitly:
    //   cargo test -p veilclient-ffi --features node-embedded \
    //     deferred_boot_then_apply -- --ignored --nocapture
    #[test]
    #[ignore = "boots a real node; run with --ignored --nocapture"]
    fn deferred_boot_then_apply_brings_node_up() {
        let dir = tempfile::tempdir().unwrap();
        let admin = dir.path().join("admin.sock").to_string_lossy().into_owned();
        let ipc = dir.path().join("app.sock").to_string_lossy().into_owned();
        let listen = "tcp://127.0.0.1:19099";
        let mut err: *mut c_char = std::ptr::null_mut();

        // difficulty 0 = canonical (matches the app); an 8-bit identity would be
        // rejected by apply-config validation (floor is DEFAULT_POW_DIFFICULTY).
        let id_ptr = unsafe { veil_config_init(0, &mut err) };
        assert!(!id_ptr.is_null(), "config_init failed");
        let id_toml = unsafe { CStr::from_ptr(id_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(id_ptr) };

        let full_ptr = unsafe {
            veil_config_compose(
                id_toml.as_ptr(),
                id_toml.len(),
                listen.as_ptr(),
                listen.len(),
                ipc.as_ptr(),
                ipc.len(),
                admin.as_ptr(),
                admin.len(),
                &mut err,
            )
        };
        assert!(!full_ptr.is_null(), "compose failed");
        let full = unsafe { CStr::from_ptr(full_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::veil_free_string(full_ptr) };
        crate::ffi_diag(&format!(
            "=== composed config ===\n{full}\n======================="
        ));

        let node =
            unsafe { veil_node_start_deferred(admin.as_ptr(), admin.len(), false, &mut err) };
        assert!(!node.is_null(), "start_deferred returned null");

        let rc = unsafe { veil_node_apply_config(node, full.as_ptr(), full.len(), &mut err) };
        let apply_err = if err.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned()
        };
        unsafe { veil_node_stop(node) };
        assert_eq!(rc, 0, "apply_config failed: {apply_err}");
    }
}
