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
use tokio::sync::oneshot;

/// Opaque handle to a running embedded node.
pub struct VeilNode {
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
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
    start_thread(Some(path), None, err_out)
}

/// Start an embedded node in deferred-init mode: it boots under an ephemeral
/// throwaway identity, binds ONLY the admin socket at `admin_socket` (`(ptr,
/// len)`, UTF-8 filesystem path), and waits. Promote it to its real identity by
/// pushing a config with `veil_node_apply_config` — so the real private key
/// never has to be written to a config file on disk.
///
/// Pick an ephemeral, identity-free path for `admin_socket` (e.g. one under a
/// per-launch temp dir). Non-blocking; returns an opaque handle or null + err.
///
/// # Safety
/// `admin_socket_ptr` must point to `admin_socket_len` readable bytes; `err_out`
/// (if non-null) must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_node_start_deferred(
    admin_socket_ptr: *const u8,
    admin_socket_len: size_t,
    err_out: *mut *mut c_char,
) -> *mut VeilNode {
    if admin_socket_ptr.is_null() {
        unsafe { set_err(err_out, "admin_socket is null") };
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(admin_socket_ptr, admin_socket_len) };
    let sock = match std::str::from_utf8(bytes) {
        Ok(s) => PathBuf::from(s),
        Err(_) => {
            unsafe { set_err(err_out, "admin_socket is not valid UTF-8") };
            return std::ptr::null_mut();
        }
    };
    start_thread(None, Some(sock), err_out)
}

fn start_thread(
    config: Option<PathBuf>,
    admin_socket: Option<PathBuf>,
    err_out: *mut *mut c_char,
) -> *mut VeilNode {
    let (tx, rx) = oneshot::channel::<()>();
    let thread_admin_socket = admin_socket.clone();
    let spawn = std::thread::Builder::new()
        .name("veil-node".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("veil_node: tokio runtime build failed: {e}");
                    return;
                }
            };
            let shutdown = async move {
                let _ = rx.await;
            };
            let result = rt.block_on(async move {
                match config {
                    Some(p) => {
                        veil_node_runtime::admin::run_foreground_with_shutdown(p, true, shutdown)
                            .await
                    }
                    None => {
                        veil_node_runtime::admin::run_foreground_deferred_with_shutdown(
                            thread_admin_socket,
                            shutdown,
                        )
                        .await
                    }
                }
            });
            if let Err(e) = result {
                eprintln!("veil_node: runtime exited with error: {e}");
            }
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
    let outcome = rt.block_on(async {
        let mut last_err = String::from("admin socket never became ready");
        for _ in 0..50 {
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
    if let Some(tx) = node.shutdown.lock().unwrap().take() {
        let _ = tx.send(());
    }
    if let Some(thread) = node.thread.lock().unwrap().take() {
        let _ = thread.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

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
}
