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

use std::ffi::{CString, c_char};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;

use libc::size_t;
use tokio::sync::oneshot;

/// Opaque handle to a running embedded node.
pub struct VeilNode {
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// Write an owned error string into `*err_out` (freed by `veil_free_string`).
unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe { *err_out = c.into_raw() };
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
    start_thread(Some(path), err_out)
}

/// Start an embedded node in deferred-init mode (ephemeral identity, no config
/// file). Supply the real config later over the node's admin IPC.
///
/// # Safety
/// `err_out` (if non-null) must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_node_start_deferred(err_out: *mut *mut c_char) -> *mut VeilNode {
    start_thread(None, err_out)
}

fn start_thread(config: Option<PathBuf>, err_out: *mut *mut c_char) -> *mut VeilNode {
    let (tx, rx) = oneshot::channel::<()>();
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
                        veil_node_runtime::admin::run_foreground_deferred_with_shutdown(shutdown)
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
        })),
        Err(e) => {
            unsafe { set_err(err_out, &format!("failed to spawn node thread: {e}")) };
            std::ptr::null_mut()
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
}
