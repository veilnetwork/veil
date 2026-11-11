//! Root-scoped admission for folder replacement, recovery, and the host scan.

use std::ffi::c_char;

/// An opaque caller-owned folder admission. Keep it alive across recovery AND
/// enumeration. Every publisher of this folder must acquire the same admission.
/// Child paths are walked from its pinned directory, never by reopening root.
/// One admission belongs to one serialized host sequence: never enumerate
/// while a publication on that same handle is in flight.
pub struct VeilFsFolder {
    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    session: super::publication::FolderSession,
}

#[cfg(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
))]
unsafe fn arg<'a>(value: *const c_char) -> Result<&'a str, String> {
    if value.is_null() {
        return Err("null string argument".to_owned());
    }
    // SAFETY: the foreign caller guarantees a live NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| "invalid UTF-8 argument".to_owned())
}

/// Acquire an exclusive folder admission, or return NULL with `*err_out` set.
/// Acquisition never waits for another owner: a busy owner returns the exact
/// diagnostic `folder publication is busy`. Other failures are final refusals.
/// Release with `veil_fs_folder_close`, including on host exceptions.
///
/// # Safety
/// `root` must be a live NUL-terminated UTF-8 string. `err_out` must be writable
/// or NULL. The handle must not be closed concurrently with any operation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_folder_open(
    root: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut VeilFsFolder {
    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    {
        let result = unsafe { arg(root) }.and_then(super::publication::FolderSession::open);
        match result {
            Ok(session) => Box::into_raw(Box::new(VeilFsFolder { session })),
            Err(error) => {
                unsafe { super::set_err(err_out, &error) };
                std::ptr::null_mut()
            }
        }
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )))]
    {
        let _ = root;
        unsafe { super::set_err(err_out, "folder publication unavailable on this host") };
        std::ptr::null_mut()
    }
}

/// Exclusively create a `.xveil-<32 lowercase hex>.incoming` file beneath the
/// admitted root, creating missing parent directories without following links.
/// Returns a file handle for veil_fs_write/sync/close, or NULL with an error.
/// Flush and close that file before publishing. Keep the folder admission
/// across the local write/publication; do not hold it across network waits.
/// This never creates or replaces a user target directly.
///
/// # Safety
/// `folder` must be an unclosed folder handle; `incoming` is live NUL-terminated
/// UTF-8. `err_out` is writable or NULL. Do not close folder concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_folder_create_incoming(
    folder: *mut VeilFsFolder,
    incoming: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut super::VeilFsFile {
    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    {
        let result = (|| {
            if folder.is_null() {
                return Err("null folder handle".to_owned());
            }
            let incoming = unsafe { arg(incoming) }?;
            unsafe { &*folder }.session.create_incoming(incoming)
        })();
        match result {
            Ok(file) => {
                #[cfg(unix)]
                let handle = {
                    use std::os::fd::IntoRawFd;
                    super::VeilFsFile {
                        fd: file.into_raw_fd(),
                        len: 0,
                    }
                };
                #[cfg(windows)]
                let handle = super::VeilFsFile { file, len: 0 };
                Box::into_raw(Box::new(handle))
            }
            Err(error) => {
                unsafe { super::set_err(err_out, &error) };
                std::ptr::null_mut()
            }
        }
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )))]
    {
        let _ = (folder, incoming);
        unsafe { super::set_err(err_out, "folder publication unavailable on this host") };
        std::ptr::null_mut()
    }
}

/// Check that a host pathname still names the admitted root. A false result
/// must refuse the host's scan, rather than interpret a moved folder as empty.
/// This check does not turn a host scan into an atomic filesystem snapshot.
///
/// # Safety
/// `folder` must be a live unclosed handle from `veil_fs_folder_open`; `root`
/// must be NUL-terminated UTF-8; `err_out` must be writable or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_folder_matches_root(
    folder: *mut VeilFsFolder,
    root: *const c_char,
    err_out: *mut *mut c_char,
) -> bool {
    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    {
        let result = if folder.is_null() {
            Err("null folder handle".to_owned())
        } else {
            // SAFETY: the caller owns an unclosed handle and live string.
            unsafe { arg(root) }.and_then(|root| unsafe { &*folder }.session.matches_root(root))
        };
        match result {
            Ok(value) => value,
            Err(error) => {
                unsafe { super::set_err(err_out, &error) };
                false
            }
        }
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )))]
    {
        let _ = (folder, root);
        unsafe { super::set_err(err_out, "folder publication unavailable on this host") };
        false
    }
}

/// Recover one discovered relative `.intent` before ordinary enumeration.
/// Returns 1 if it was unsettled and recovered, 0 if already settled, -1 on a
/// refusal. A refusal must stop the scan; it never means "there are no files".
/// Keeps newer occupied names and all recovery copies. Never falls back to an
/// ordinary rename. The root admission remains held after this call returns.
///
/// # Safety
/// `folder` must be an unclosed admitted handle; `relative_intent` must be a
/// live NUL-terminated UTF-8 string. `err_out` must be writable or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_folder_recover(
    folder: *mut VeilFsFolder,
    relative_intent: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    {
        let result = if folder.is_null() {
            Err("null folder handle".to_owned())
        } else {
            // SAFETY: the caller owns an unclosed handle and live string.
            unsafe { arg(relative_intent) }
                .and_then(|path| unsafe { &*folder }.session.recover(path))
        };
        match result {
            Ok(value) => i32::from(value),
            Err(error) => {
                unsafe { super::set_err(err_out, &error) };
                -1
            }
        }
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )))]
    {
        let _ = (folder, relative_intent);
        unsafe { super::set_err(err_out, "folder publication unavailable on this host") };
        -1
    }
}

/// Install a prepared `.xveil-<32 lowercase hex>.incoming` sibling, preserving
/// the displaced version and an intent for process-interruption recovery.
/// Returns 1 on publication (writing the incoming version's stamp to outputs),
/// 0 when the local version changed, -1 on error. With `expected_present=false`
/// the size/mtime inputs are ignored and an occupied destination wins its name.
/// A stamp is size plus Unix-epoch milliseconds, not an immutable snapshot.
/// Previous copies are retained for explicit user review/cleanup.
///
/// # Safety
/// `folder` must remain live; paths must be NUL-terminated UTF-8. Both output
/// pointers must be writable and non-NULL. `err_out` is writable or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_folder_publish(
    folder: *mut VeilFsFolder,
    target: *const c_char,
    incoming: *const c_char,
    expected_present: bool,
    expected_size: u64,
    expected_modified_ms: i64,
    size_out: *mut u64,
    modified_ms_out: *mut i64,
    err_out: *mut *mut c_char,
) -> i32 {
    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    {
        let result = (|| {
            if folder.is_null() || size_out.is_null() || modified_ms_out.is_null() {
                return Err("null handle or required output".to_owned());
            }
            // SAFETY: the caller guarantees live strings and handle until return.
            let target = unsafe { arg(target) }?;
            let incoming = unsafe { arg(incoming) }?;
            let expected = expected_present.then_some(super::publication::Version {
                size: expected_size,
                modified_ms: expected_modified_ms,
            });
            unsafe { &*folder }
                .session
                .publish(target, incoming, expected)
        })();
        match result {
            Ok(super::publication::Outcome::Published(version)) => {
                // SAFETY: both outputs were checked non-NULL and are writable.
                unsafe {
                    *size_out = version.size;
                    *modified_ms_out = version.modified_ms;
                }
                1
            }
            Ok(super::publication::Outcome::LocalChanged) => 0,
            Err(error) => {
                unsafe { super::set_err(err_out, &error) };
                -1
            }
        }
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )))]
    {
        let _ = (
            folder,
            target,
            incoming,
            expected_present,
            expected_size,
            expected_modified_ms,
            size_out,
            modified_ms_out,
        );
        unsafe { super::set_err(err_out, "folder publication unavailable on this host") };
        -1
    }
}

/// Release a folder admission. NULL is harmless. No outstanding operation may
/// still reference the handle.
///
/// # Safety
/// A non-NULL handle must be caller-owned, unclosed and returned by
/// `veil_fs_folder_open`. It must never be closed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_folder_close(folder: *mut VeilFsFolder) {
    if !folder.is_null() {
        // SAFETY: the caller transfers its unique live handle back to its owner.
        drop(unsafe { Box::from_raw(folder) });
    }
}

#[cfg(all(
    test,
    any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )
))]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "veil-folder-ffi-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn root(&self) -> CString {
            CString::new(self.0.to_str().unwrap()).unwrap()
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    struct Folder(*mut VeilFsFolder);
    impl Drop for Folder {
        fn drop(&mut self) {
            unsafe { veil_fs_folder_close(self.0) };
        }
    }
    fn error(value: &mut *mut c_char) -> String {
        assert!(!value.is_null());
        // Test-only ownership of the error allocated by the same Rust module.
        let result = unsafe { CString::from_raw(*value) }.into_string().unwrap();
        *value = std::ptr::null_mut();
        result
    }

    #[test]
    fn null_and_invalid_utf8_arguments_return_owned_errors_without_touching_disk() {
        let mut err = std::ptr::null_mut();
        assert!(unsafe { veil_fs_folder_open(std::ptr::null(), &mut err) }.is_null());
        assert_eq!(error(&mut err), "null string argument");
        let invalid = [0xff_u8, 0];
        assert!(unsafe { veil_fs_folder_open(invalid.as_ptr().cast(), &mut err) }.is_null());
        assert_eq!(error(&mut err), "invalid UTF-8 argument");
        assert_eq!(
            unsafe { veil_fs_folder_recover(std::ptr::null_mut(), c"x".as_ptr(), &mut err) },
            -1
        );
        assert_eq!(error(&mut err), "null folder handle");
        unsafe { veil_fs_folder_close(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_admission_publication_receipts_and_release_have_the_documented_contract() {
        let tree = Tree::new();
        let root = tree.root();
        let mut err = std::ptr::null_mut();
        let folder = Folder(unsafe { veil_fs_folder_open(root.as_ptr(), &mut err) });
        assert!(!folder.0.is_null());
        assert!(err.is_null());
        assert!(unsafe { veil_fs_folder_matches_root(folder.0, root.as_ptr(), &mut err) });
        let busy = unsafe { veil_fs_folder_open(root.as_ptr(), &mut err) };
        assert!(busy.is_null());
        assert_eq!(error(&mut err), "folder publication is busy");
        let first = c".xveil-0123456789abcdef0123456789abcdef.incoming";
        std::fs::write(tree.0.join(first.to_str().unwrap()), b"first").unwrap();
        let mut size = 0;
        let mut modified = 0;
        assert_eq!(
            unsafe {
                veil_fs_folder_publish(
                    folder.0,
                    c"target".as_ptr(),
                    first.as_ptr(),
                    false,
                    999,
                    -999,
                    &mut size,
                    &mut modified,
                    &mut err,
                )
            },
            1
        );
        assert!(err.is_null());
        assert_eq!(size, 5);
        let second = c".xveil-1123456789abcdef0123456789abcdef.incoming";
        std::fs::write(tree.0.join(second.to_str().unwrap()), b"second").unwrap();
        // Required output validation happens before any namespace mutation.
        assert_eq!(
            unsafe {
                veil_fs_folder_publish(
                    folder.0,
                    c"target".as_ptr(),
                    second.as_ptr(),
                    true,
                    size,
                    modified,
                    std::ptr::null_mut(),
                    &mut modified,
                    &mut err,
                )
            },
            -1
        );
        assert_eq!(error(&mut err), "null handle or required output");
        assert_eq!(std::fs::read(tree.0.join("target")).unwrap(), b"first");
        assert_eq!(
            unsafe {
                veil_fs_folder_publish(
                    folder.0,
                    c"target".as_ptr(),
                    second.as_ptr(),
                    true,
                    size,
                    modified,
                    &mut size,
                    &mut modified,
                    &mut err,
                )
            },
            1
        );
        assert!(err.is_null());
        assert_eq!(size, 6);
        assert_eq!(std::fs::read(tree.0.join("target")).unwrap(), b"second");
        assert_eq!(
            std::fs::read(
                tree.0
                    .join(".xveil-1123456789abcdef0123456789abcdef.previous")
            )
            .unwrap(),
            b"first"
        );
        assert_eq!(
            unsafe {
                veil_fs_folder_recover(
                    folder.0,
                    c".xveil-1123456789abcdef0123456789abcdef.intent".as_ptr(),
                    &mut err,
                )
            },
            0
        );
        drop(folder);
        let next = Folder(unsafe { veil_fs_folder_open(root.as_ptr(), &mut err) });
        assert!(!next.0.is_null());
        assert!(err.is_null());
    }
}
