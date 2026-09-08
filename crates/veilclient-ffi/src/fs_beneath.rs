//! Open a file BENEATH a root without trusting the name it was reached by.
//!
//! ## What the host cannot do for itself
//!
//! xVeil serves files a person granted it: an API caller names a path, the app
//! checks the path lies inside a granted root, and then opens it. Between the
//! check and the open the name is still only a name — and `dart:io` has no
//! `openat`, no `O_NOFOLLOW` and no `fstat`, so the host has no way to bind the
//! name it checked to the object it opened.
//!
//! The host narrowed that window as far as Dart allows: it stamps `(device,
//! inode)` immediately before and immediately after the open and refuses on a
//! change. An adversary who can swap the name twice — A → B → A, inside two
//! adjacent `lstat` calls — still gets the substituted descriptor with matching
//! stamps. Closing it needs descriptor-relative access, which is why it is
//! here rather than there (reports 6/7/8/9/11/12/13, one finding restated
//! seven times).
//!
//! ## What this does instead
//!
//! Walks the path one component at a time from a descriptor on the root, with
//! `openat(O_NOFOLLOW)` at every step. A component that is a symlink is not
//! followed — it is refused. `..` is refused outright rather than resolved,
//! because a `..` that is legal at check time can be made to escape by
//! renaming a directory underneath. So the file this returns is reachable from
//! the root by a chain of real directories, and no rename racing the walk can
//! make it be anything else: each descriptor pins the directory it names, and
//! the next `openat` is relative to that descriptor rather than to a name that
//! may since have moved.
//!
//! `openat2(RESOLVE_BENEATH)` would express this in one syscall, and is Linux
//! 5.6+ only. The walk is the same guarantee on every POSIX host, including the
//! Android and macOS versions this app ships to.
//!
//! ## Windows
//!
//! Not implemented, and it says so rather than pretending: there is no
//! `openat`, the equivalent needs `NtCreateFile` with a root handle, and this
//! machine cannot run a test of it. The host keeps its stamped open there — the
//! same weaker check it already documents on Windows, where the stamp degrades
//! to size and mtime anyway. An honest refusal is what lets the caller know
//! which guarantee it has.

use std::ffi::{CStr, CString, c_char, c_int};

use libc::size_t;

/// An open file, held by descriptor. The name it was opened by is not kept:
/// nothing here ever looks at a path again.
///
/// `Debug` prints the descriptor and the length and no path, because there is
/// no path to print — which is the property this whole module exists for.
#[derive(Debug)]
pub struct VeilFsFile {
    #[cfg(unix)]
    fd: c_int,
    len: u64,
}

#[cfg(unix)]
impl Drop for VeilFsFile {
    fn drop(&mut self) {
        // SAFETY: `fd` came from `openat` in this module and is closed once.
        unsafe { libc::close(self.fd) };
    }
}

unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe { *err_out = c.into_raw() };
}

/// Why a path is refused before a single syscall is made.
///
/// Rejected rather than normalised. A caller that meant one of these has a bug,
/// and quietly reinterpreting it is how a check comes to disagree with what it
/// checked: `..` in particular is legal to *resolve* and impossible to *trust*,
/// because the directory it resolves through can be renamed after the check.
fn component_is_refused(c: &str) -> Option<&'static str> {
    if c.is_empty() {
        return Some("empty path component");
    }
    if c == ".." {
        return Some("`..` is not resolved: a component above the root cannot be trusted");
    }
    if c == "." {
        return Some("`.` is not resolved");
    }
    if c.contains('\0') {
        return Some("NUL in a path component");
    }
    None
}

/// Open `relative` beneath `root`, following no symlink on the way.
///
/// `root` is opened by name — it is the anchor the caller already trusts and
/// re-validates, and a root that is itself a symlink is an ordinary
/// configuration. Everything below it is walked by descriptor.
///
/// Returns null and writes `*err_out` on any refusal. Writes the file's size
/// to `*out_len` on success, read from the DESCRIPTOR, so it describes the
/// object this call is returning rather than whatever the name means later.
///
/// # Safety
/// `root` and `relative` must be NUL-terminated C strings; `out_len` and
/// `err_out` must be writable or null. The returned handle is freed with
/// [`veil_fs_close`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_open_beneath(
    root: *const c_char,
    relative: *const c_char,
    out_len: *mut u64,
    err_out: *mut *mut c_char,
) -> *mut VeilFsFile {
    #[cfg(not(unix))]
    {
        let _ = (root, relative, out_len);
        unsafe {
            set_err(
                err_out,
                "veil_fs_open_beneath is POSIX-only; the caller keeps its own check on this host",
            )
        };
        std::ptr::null_mut()
    }

    #[cfg(unix)]
    {
        if root.is_null() || relative.is_null() {
            unsafe { set_err(err_out, "null path") };
            return std::ptr::null_mut();
        }
        let root = match unsafe { CStr::from_ptr(root) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                unsafe { set_err(err_out, "root is not UTF-8") };
                return std::ptr::null_mut();
            }
        };
        let relative = match unsafe { CStr::from_ptr(relative) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                unsafe { set_err(err_out, "path is not UTF-8") };
                return std::ptr::null_mut();
            }
        };
        match open_beneath(root, relative) {
            Ok(file) => {
                if !out_len.is_null() {
                    unsafe { *out_len = file.len };
                }
                Box::into_raw(Box::new(file))
            }
            Err(msg) => {
                unsafe { set_err(err_out, &msg) };
                std::ptr::null_mut()
            }
        }
    }
}

#[cfg(unix)]
fn open_beneath(root: &str, relative: &str) -> Result<VeilFsFile, String> {
    // ONE walk for both entry points. This used to carry its own copy, which
    // is two places for the same rule to be right in — and the create side was
    // written by copying it.
    let (dir, leaf) = walk_to_parent(root, relative)?;
    // SAFETY: `dir` is an open directory descriptor; `leaf` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir,
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = last_error();
        let is_link = component_is_symlink(dir, &leaf);
        // SAFETY: `dir` is open and finished with.
        unsafe { libc::close(dir) };
        return Err(if is_link {
            format!("{leaf:?} is a symbolic link; it was not followed")
        } else {
            format!("cannot open {leaf:?} beneath the root: {err}")
        });
    }
    // SAFETY: `dir` is open and finished with.
    unsafe { libc::close(dir) };

    // The size comes from the descriptor, never from the name.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is the open file; `st` is writable.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = last_error();
        unsafe { libc::close(fd) };
        return Err(format!("cannot stat the opened file: {err}"));
    }
    // A directory, a device or a fifo is not a file to send. `O_NOFOLLOW`
    // already refused a symlink; this refuses the rest, so a caller cannot be
    // made to read from something that blocks forever.
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        unsafe { libc::close(fd) };
        return Err("not a regular file".to_owned());
    }

    Ok(VeilFsFile {
        fd,
        len: st.st_size.max(0) as u64,
    })
}

/// The walk, shared with [`open_beneath`], stopping one component short so the
/// caller can decide what to do with the leaf.
///
/// Returns the descriptor of the directory that CONTAINS the leaf, plus the
/// leaf's own name. The caller closes it.
#[cfg(unix)]
fn walk_to_parent(root: &str, relative: &str) -> Result<(c_int, CString), String> {
    use std::os::unix::ffi::OsStrExt as _;

    if relative.starts_with('/') {
        return Err("path is absolute; it must be relative to the root".to_owned());
    }
    let components: Vec<&str> = relative.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err("path names the root itself, not a file in it".to_owned());
    }
    for c in &components {
        if let Some(why) = component_is_refused(c) {
            return Err(format!("refused component {c:?}: {why}"));
        }
    }

    let root_c = CString::new(std::ffi::OsStr::new(root).as_bytes())
        .map_err(|_| "NUL in root".to_owned())?;
    // SAFETY: `root_c` is a valid NUL-terminated path.
    let mut dir = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dir < 0 {
        return Err(format!("cannot open the root: {}", last_error()));
    }

    let leaf = CString::new(components[components.len() - 1])
        .map_err(|_| "NUL in a path component".to_owned())?;
    for comp in &components[..components.len() - 1] {
        let c = CString::new(*comp).map_err(|_| "NUL in a path component".to_owned())?;
        // SAFETY: `dir` is an open directory descriptor; `c` is NUL-terminated.
        let next = unsafe {
            libc::openat(
                dir,
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            let err = last_error();
            let is_link = component_is_symlink(dir, &c);
            // SAFETY: `dir` is open and finished with.
            unsafe { libc::close(dir) };
            return Err(if is_link {
                format!("{comp:?} is a symbolic link; it was not followed")
            } else {
                format!("cannot open {comp:?} beneath the root: {err}")
            });
        }
        // SAFETY: closing the descriptor this step walked away from.
        unsafe { libc::close(dir) };
        dir = next;
    }
    Ok((dir, leaf))
}

#[cfg(unix)]
fn create_beneath(root: &str, relative: &str) -> Result<VeilFsFile, String> {
    let (dir, leaf) = walk_to_parent(root, relative)?;
    // `O_EXCL` is what does the work at the leaf, and `O_NOFOLLOW` beside it
    // is belt-and-braces rather than a second guarantee: `O_CREAT | O_EXCL`
    // already fails with EEXIST on a name that exists AS A SYMLINK, whatever
    // it points at. A break-check confirmed that — removing `O_NOFOLLOW` here
    // reddens nothing, and saying both flags carry the property would be a
    // claim no test can hold. It stays because it costs nothing and keeps this
    // correct if the exclusivity is ever relaxed; the directories above are
    // where `O_NOFOLLOW` is load-bearing, and those ARE break-checked.
    // SAFETY: `dir` is an open directory descriptor; `leaf` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir,
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    let err = last_error();
    // SAFETY: `dir` is open and finished with.
    unsafe { libc::close(dir) };
    if fd < 0 {
        return Err(format!("cannot create the file beneath the root: {err}"));
    }
    Ok(VeilFsFile { fd, len: 0 })
}

/// Whether `name` under `dir` is a symlink, asked WITHOUT following it.
///
/// Only ever called after an open has already failed, so its cost falls on the
/// refusal path; a false answer here can only make a message less precise, and
/// never turns a refusal into an acceptance.
///
/// It exists because the first version classified from the error TEXT, looking
/// for ELOOP — and a symlink to a directory refused by `O_NOFOLLOW |
/// O_DIRECTORY` reports ENOTDIR on macOS, so the refusal was right and the
/// sentence was wrong.
#[cfg(unix)]
fn component_is_symlink(dir: c_int, name: &CStr) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open directory descriptor, `name` is NUL-terminated,
    // `st` is writable.
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

#[cfg(unix)]
fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Create `relative` beneath `root` for writing, following no symlink and
/// refusing a name that already exists.
///
/// The write side of the same gap. Folder sync checks that a mirrored path is
/// inside its root and then opens it — and `File.open` follows a link, so a
/// component turned into a symlink between the check and the open sent the
/// download outside the mirrored tree, truncating whatever it aimed at. The
/// scratch file has the same shape and documents the same remainder: it wants
/// `O_NOFOLLOW` with `O_EXCL`, which `dart:io` does not expose.
///
/// `O_EXCL` is not an optimisation here. Without it a name an attacker
/// pre-created is opened and truncated; with it the create fails and the caller
/// picks another name, which is what the random scratch name was already for.
///
/// # Safety
/// Same contract as [`veil_fs_open_beneath`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_create_beneath(
    root: *const c_char,
    relative: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut VeilFsFile {
    #[cfg(not(unix))]
    {
        let _ = (root, relative);
        unsafe {
            set_err(
                err_out,
                "veil_fs_create_beneath is POSIX-only; the caller keeps its own check on this host",
            )
        };
        std::ptr::null_mut()
    }

    #[cfg(unix)]
    {
        if root.is_null() || relative.is_null() {
            unsafe { set_err(err_out, "null path") };
            return std::ptr::null_mut();
        }
        let root = match unsafe { CStr::from_ptr(root) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                unsafe { set_err(err_out, "root is not UTF-8") };
                return std::ptr::null_mut();
            }
        };
        let relative = match unsafe { CStr::from_ptr(relative) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                unsafe { set_err(err_out, "path is not UTF-8") };
                return std::ptr::null_mut();
            }
        };
        match create_beneath(root, relative) {
            Ok(file) => Box::into_raw(Box::new(file)),
            Err(msg) => {
                unsafe { set_err(err_out, &msg) };
                std::ptr::null_mut()
            }
        }
    }
}

/// Write `len` bytes at `offset` through an open handle. Returns the number
/// written, or -1 with `*err_out` set.
///
/// # Safety
/// `handle` must come from [`veil_fs_create_beneath`]; `buf` must be readable
/// for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_write(
    handle: *mut VeilFsFile,
    offset: u64,
    buf: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> isize {
    #[cfg(not(unix))]
    {
        let _ = (handle, offset, buf, len);
        unsafe { set_err(err_out, "veil_fs_write is POSIX-only") };
        -1
    }

    #[cfg(unix)]
    {
        if handle.is_null() || buf.is_null() {
            unsafe { set_err(err_out, "null handle or buffer") };
            return -1;
        }
        // SAFETY: the caller guarantees `handle` is live and unclosed.
        let file = unsafe { &*handle };
        // SAFETY: `buf` is readable for `len` bytes per the contract above.
        let n = unsafe {
            libc::pwrite(
                file.fd,
                buf as *const libc::c_void,
                len,
                offset as libc::off_t,
            )
        };
        if n < 0 {
            unsafe { set_err(err_out, &format!("write failed: {}", last_error())) };
            return -1;
        }
        n as isize
    }
}

/// Read up to `len` bytes at `offset` from an open handle. Returns the number
/// read, or -1 with `*err_out` set.
///
/// Positional, so concurrent reads on one handle cannot move each other's
/// cursor — the host serves ranges out of order.
///
/// # Safety
/// `handle` must come from [`veil_fs_open_beneath`] and not have been closed;
/// `buf` must be writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_read(
    handle: *mut VeilFsFile,
    offset: u64,
    buf: *mut u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> isize {
    #[cfg(not(unix))]
    {
        let _ = (handle, offset, buf, len);
        unsafe { set_err(err_out, "veil_fs_read is POSIX-only") };
        -1
    }

    #[cfg(unix)]
    {
        if handle.is_null() || buf.is_null() {
            unsafe { set_err(err_out, "null handle or buffer") };
            return -1;
        }
        // SAFETY: the caller guarantees `handle` is live and unclosed.
        let file = unsafe { &*handle };
        // SAFETY: `buf` is writable for `len` bytes per the contract above.
        let n = unsafe {
            libc::pread(
                file.fd,
                buf as *mut libc::c_void,
                len,
                offset as libc::off_t,
            )
        };
        if n < 0 {
            unsafe { set_err(err_out, &format!("read failed: {}", last_error())) };
            return -1;
        }
        n as isize
    }
}

/// Close a handle from [`veil_fs_open_beneath`]. Null is a no-op.
///
/// # Safety
/// `handle` must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_close(handle: *mut VeilFsFile) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the handle came from `Box::into_raw` in this module.
    drop(unsafe { Box::from_raw(handle) });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A directory nobody else in this run will get.
    ///
    /// The counter is not decoration: the first version keyed on pid and a
    /// nanosecond clock, tests here run in parallel threads of ONE process,
    /// and two of them drew the same name — one then `remove_dir_all`ed the
    /// other's tree and the failure appeared in a test that had nothing wrong
    /// with it.
    fn scratch() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "veil-fs-beneath-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(path: &std::path::Path, body: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
    }

    fn read_all(file: &VeilFsFile) -> Vec<u8> {
        let mut out = vec![0u8; file.len as usize];
        let n =
            unsafe { libc::pread(file.fd, out.as_mut_ptr() as *mut libc::c_void, out.len(), 0) };
        out.truncate(n.max(0) as usize);
        out
    }

    /// The ordinary case, so every refusal below means something.
    #[test]
    fn a_real_file_beneath_the_root_opens_and_reads() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        write(&root.join("sub/f.txt"), b"hello");

        let file = open_beneath(root.to_str().unwrap(), "sub/f.txt").expect("open");
        assert_eq!(file.len, 5);
        assert_eq!(read_all(&file), b"hello");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A symlink LEAF is refused rather than followed.
    ///
    /// This is what the host could not do: from Dart the name resolves, the
    /// open succeeds, and the file that arrives is whatever the link pointed
    /// at when the kernel looked — which is not necessarily what was checked.
    #[test]
    fn a_symlinked_file_is_refused_not_followed() {
        let root = scratch();
        let outside = scratch();
        write(&outside.join("secret.txt"), b"not yours");
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("link.txt")).unwrap();

        let err = open_beneath(root.to_str().unwrap(), "link.txt").unwrap_err();
        assert!(
            err.contains("symbolic link"),
            "a symlink leaf must be named as one: {err}"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// A symlinked DIRECTORY in the middle is refused too.
    ///
    /// The leaf check alone would let `link/f.txt` out of the root, which is
    /// the escape the finding is about rather than a hypothetical.
    #[test]
    fn a_symlinked_directory_component_is_refused() {
        let root = scratch();
        let outside = scratch();
        write(&outside.join("f.txt"), b"not yours");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = open_beneath(root.to_str().unwrap(), "link/f.txt").unwrap_err();
        assert!(
            err.contains("symbolic link"),
            "a symlinked directory must be refused: {err}"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// `..` is refused rather than resolved.
    ///
    /// Resolving it is legal and untrustworthy: the directory it resolves
    /// THROUGH can be renamed after the caller checked, so a path that was
    /// inside the root at check time need not be at open time.
    #[test]
    fn a_parent_component_is_refused_rather_than_resolved() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        write(&root.join("f.txt"), b"inside");

        let err = open_beneath(root.to_str().unwrap(), "sub/../f.txt").unwrap_err();
        assert!(
            err.contains(".."),
            "the refusal must name the component: {err}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// And an absolute path is not quietly reinterpreted as a relative one.
    #[test]
    fn an_absolute_path_is_refused() {
        let root = scratch();
        let err = open_beneath(root.to_str().unwrap(), "/etc/passwd").unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A directory, a fifo or a device is not a file to send.
    ///
    /// Without this a caller could be pointed at a fifo and would block for as
    /// long as the other end stayed silent — a stall with no error, which is
    /// the worst shape a refusal can take.
    #[test]
    fn only_a_regular_file_is_returned() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        let err = open_beneath(root.to_str().unwrap(), "sub").unwrap_err();
        assert!(err.contains("regular file"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    /// Creating: the ordinary case, so every refusal below means something.
    #[test]
    fn a_new_file_is_created_beneath_the_root() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        let file = create_beneath(root.to_str().unwrap(), "sub/new.bin").expect("create");
        let body = b"written";
        let n =
            unsafe { libc::pwrite(file.fd, body.as_ptr() as *const libc::c_void, body.len(), 0) };
        assert_eq!(n, body.len() as isize);
        drop(file);
        assert_eq!(std::fs::read(root.join("sub/new.bin")).unwrap(), b"written");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A name that already exists is REFUSED, not opened and truncated.
    ///
    /// Without `O_EXCL` a name an attacker pre-created is a file the caller
    /// then writes into — the scratch file's random name makes that unlikely
    /// and this makes it impossible.
    #[test]
    fn an_existing_name_is_refused_rather_than_truncated() {
        let root = scratch();
        write(&root.join("taken.bin"), b"do not lose me");
        let err = create_beneath(root.to_str().unwrap(), "taken.bin").unwrap_err();
        assert!(err.contains("cannot create"), "{err}");
        assert_eq!(
            std::fs::read(root.join("taken.bin")).unwrap(),
            b"do not lose me",
            "the existing file was truncated"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// And a symlink pre-created under the name is refused too.
    ///
    /// This is the folder-sync finding exactly: `File.open` follows the link,
    /// so the download truncated whatever it aimed at, outside the mirrored
    /// tree.
    #[test]
    fn creating_over_a_symlink_does_not_write_through_it() {
        let root = scratch();
        let outside = scratch();
        write(&outside.join("victim.txt"), b"somebody else's file");
        std::os::unix::fs::symlink(outside.join("victim.txt"), root.join("part.bin")).unwrap();

        let err = create_beneath(root.to_str().unwrap(), "part.bin").unwrap_err();
        assert!(err.contains("cannot create"), "{err}");
        assert_eq!(
            std::fs::read(outside.join("victim.txt")).unwrap(),
            b"somebody else's file",
            "the write went through the link"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// A symlinked DIRECTORY on the way is refused when creating, as when
    /// reading — the walk is the same one.
    #[test]
    fn creating_through_a_symlinked_directory_is_refused() {
        let root = scratch();
        let outside = scratch();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = create_beneath(root.to_str().unwrap(), "link/f.bin").unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        assert!(!outside.join("f.bin").exists(), "it created one out there");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// THE POINT OF THE WALK: a directory renamed after the walk has passed
    /// through it cannot change what was opened.
    ///
    /// The host's stamped open compares the name's identity before and after,
    /// so an A → B → A swap defeats it. Here the second component is opened
    /// relative to a DESCRIPTOR on the first, so renaming the first afterwards
    /// reaches nothing: the descriptor still names the directory it named.
    #[test]
    fn a_rename_after_the_walk_cannot_change_what_was_opened() {
        let root = scratch();
        std::fs::create_dir(root.join("a")).unwrap();
        write(&root.join("a/f.txt"), b"authorized");
        std::fs::create_dir(root.join("evil")).unwrap();
        write(&root.join("evil/f.txt"), b"substituted");

        let file = open_beneath(root.to_str().unwrap(), "a/f.txt").expect("open");
        // The swap the attacker wants, performed AFTER the open — which is the
        // only place a host that reads through a name is still exposed.
        std::fs::rename(root.join("a"), root.join("gone")).unwrap();
        std::fs::rename(root.join("evil"), root.join("a")).unwrap();

        assert_eq!(
            read_all(&file),
            b"authorized",
            "the read followed the name rather than the descriptor"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
