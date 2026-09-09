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
//! The same guarantee by the same means, spelled in the NT layer. Win32 proper
//! has no `openat` — every entry point takes a path and looks it up again,
//! which is the thing being got rid of — but `NtCreateFile` accepts a
//! RootDirectory HANDLE and resolves the name relative to it, exactly as
//! `openat` resolves relative to a descriptor. `OBJ_DONT_REPARSE` is the
//! `O_NOFOLLOW`: a junction or a symlink on the way is refused with
//! STATUS_REPARSE_POINT_ENCOUNTERED rather than followed.
//!
//! An earlier version of this module said Windows could not be done here and
//! that this machine could not test it. The first half was wrong and the second
//! was about the wrong machine: the build and the test run on the Windows ARM
//! stand.

#[cfg(unix)]
use std::ffi::c_int;
use std::ffi::{CStr, CString, c_char};

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
    /// Windows has no descriptor to keep as an integer, and no `pread`: the
    /// handle becomes a `File` and positional IO goes through `seek_read` /
    /// `seek_write`, which do not move a shared cursor either.
    #[cfg(windows)]
    file: std::fs::File,
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, relative, out_len);
        unsafe { set_err(err_out, "veil_fs_open_beneath is POSIX-only") };
        std::ptr::null_mut()
    }

    #[cfg(any(unix, windows))]
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

// ---- Windows -------------------------------------------------------------
//
// `NtCreateFile` is the only entry point on this platform that resolves a name
// relative to an open DIRECTORY rather than to the filesystem root, which is
// what makes the walk below mean the same thing it means on POSIX.
//
// The constants are declared here rather than imported: `windows-sys` exposes
// the function and the structures, and these two object-attribute bits live in
// the DDK headers. Their values are part of the NT ABI and have not moved since
// Windows 8, which is also when `OBJ_DONT_REPARSE` appeared.
/// Positional read, so concurrent reads on one handle cannot move each other's
/// cursor — the host serves ranges out of order.
///
/// One name for two spellings: `pread` on POSIX, `seek_read` on Windows.
/// Neither touches a shared file position.
#[cfg(any(unix, windows))]
fn read_at(file: &VeilFsFile, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let n = {
            let off = libc::off64_t::try_from(offset).map_err(offset_beyond_reach)?;
            // SAFETY: `out` is a valid slice; `fd` is this module's open file.
            unsafe {
                libc::pread64(
                    file.fd,
                    out.as_mut_ptr() as *mut libc::c_void,
                    out.len(),
                    off,
                )
            }
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let n = {
            let off = libc::off_t::try_from(offset).map_err(offset_beyond_reach)?;
            // SAFETY: `out` is a valid slice; `fd` is this module's open file.
            unsafe {
                libc::pread(
                    file.fd,
                    out.as_mut_ptr() as *mut libc::c_void,
                    out.len(),
                    off,
                )
            }
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        file.file.seek_read(out, offset)
    }
}

/// An offset this platform's file offsets cannot express.
///
/// `off_t` is 64-bit on macOS and on 64-bit Linux — and 32-bit on a 32-bit
/// Android, where `offset as off_t` wraps in silence: an offset of 4 GiB + 5
/// becomes 5, and the caller is handed the WRONG BYTES with a success code.
/// Linux and Android both carry `pread64`/`pwrite64`, whose offset is 64-bit
/// whatever the word size is, so those are used there; everywhere else the
/// conversion is checked and an offset that will not fit is refused rather
/// than wrapped. Silence is the thing being removed: a refusal is a fault the
/// caller can see.
#[cfg(unix)]
fn offset_beyond_reach(_: std::num::TryFromIntError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "offset beyond what this platform's file offsets can address",
    )
}

/// Put the written bytes on the disk: `fsync` on POSIX, `FlushFileBuffers` on
/// Windows. Both mean the same promise and neither is implied by a write.
#[cfg(any(unix, windows))]
fn sync_file(file: &VeilFsFile) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: `fd` is this module's open file.
        let rc = unsafe { libc::fsync(file.fd) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        file.file.sync_all()
    }
}

/// Positional write, the same way round.
#[cfg(any(unix, windows))]
fn write_at(file: &VeilFsFile, offset: u64, src: &[u8]) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let n = {
            let off = libc::off64_t::try_from(offset).map_err(offset_beyond_reach)?;
            // SAFETY: `src` is a valid slice; `fd` is this module's open file.
            unsafe { libc::pwrite64(file.fd, src.as_ptr() as *const libc::c_void, src.len(), off) }
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let n = {
            let off = libc::off_t::try_from(offset).map_err(offset_beyond_reach)?;
            // SAFETY: `src` is a valid slice; `fd` is this module's open file.
            unsafe { libc::pwrite(file.fd, src.as_ptr() as *const libc::c_void, src.len(), off) }
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        file.file.seek_write(src, offset)
    }
}

/// Split `relative` into the components to walk, refusing the shapes that
/// cannot be trusted. Shared, so the two platforms cannot come to disagree
/// about what a path may contain.
fn split_components(relative: &str) -> Result<Vec<&str>, String> {
    if relative.starts_with('/') || relative.starts_with('\\') {
        return Err("path is absolute; it must be relative to the root".to_owned());
    }
    // Both separators, because Windows accepts either and a backslash must not
    // hide a component boundary from the checks below.
    let components: Vec<&str> = relative
        .split(['/', '\\'])
        .filter(|c| !c.is_empty())
        .collect();
    if components.is_empty() {
        return Err("path names the root itself, not a file in it".to_owned());
    }
    for c in &components {
        if let Some(why) = component_is_refused(c) {
            return Err(format!("refused component {c:?}: {why}"));
        }
    }
    Ok(components)
}

#[cfg(windows)]
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
/// Refuse a reparse point instead of following it — the `O_NOFOLLOW` of this
/// platform. Without it a junction under a granted folder is walked through
/// exactly as a symlink would be.
#[cfg(windows)]
const OBJ_DONT_REPARSE: u32 = 0x0000_1000;

#[cfg(windows)]
fn win_open_root(root: &str) -> Result<windows_sys::Win32::Foundation::HANDLE, String> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = std::ffi::OsStr::new(root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // FILE_FLAG_BACKUP_SEMANTICS is what lets a DIRECTORY be opened at all.
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(format!("cannot open the root: {}", last_error()));
    }
    Ok(handle)
}

/// One step of the walk: open `name` relative to `dir`, refusing a reparse
/// point. `directory` picks between a directory component and the leaf.
#[cfg(windows)]
fn win_open_at(
    dir: windows_sys::Win32::Foundation::HANDLE,
    name: &str,
    directory: bool,
    create: bool,
) -> Result<windows_sys::Win32::Foundation::HANDLE, String> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
    use windows_sys::Win32::Foundation::{STATUS_SUCCESS, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };

    // NT create dispositions and options, from the DDK. `FILE_CREATE` is the
    // `O_CREAT | O_EXCL` of this platform: it fails if the name exists, which
    // is what keeps a pre-created name from being opened and truncated.
    const FILE_OPEN: u32 = 0x0000_0001;
    const FILE_CREATE: u32 = 0x0000_0002;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const STATUS_REPARSE_POINT_ENCOUNTERED: i32 = 0xC000_050B_u32 as i32;

    let mut wide: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().collect();
    let bytes = (wide.len() * 2) as u16;
    let mut unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: wide.as_mut_ptr(),
    };
    let mut attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir,
        ObjectName: &mut unicode,
        // The whole point: the name is resolved under `dir`, and a reparse
        // point encountered on the way is an error rather than a hop.
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    let mut iosb = unsafe { std::mem::zeroed() };
    let access = if create {
        FILE_GENERIC_WRITE | SYNCHRONIZE
    } else {
        FILE_GENERIC_READ | SYNCHRONIZE
    };
    let options = FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    // SAFETY: every pointer above is valid for the duration of the call, and
    // `wide`/`unicode`/`attrs` outlive it.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &mut attrs,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            if create { FILE_CREATE } else { FILE_OPEN },
            options,
            std::ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(if status == STATUS_REPARSE_POINT_ENCOUNTERED {
            format!("{name:?} is a reparse point; it was not followed")
        } else {
            format!("cannot open {name:?} beneath the root (NTSTATUS {status:#x})")
        });
    }
    Ok(handle)
}

/// The walk, Windows spelling. Same rule as [`walk_to_parent`]: components are
/// refused before any call, and each step resolves under the handle the last
/// one returned.
#[cfg(windows)]
fn win_walk_to_parent(
    root: &str,
    relative: &str,
) -> Result<(windows_sys::Win32::Foundation::HANDLE, String), String> {
    use windows_sys::Win32::Foundation::CloseHandle;

    let components = split_components(relative)?;
    let mut dir = win_open_root(root)?;
    let leaf = components[components.len() - 1].to_owned();
    for comp in &components[..components.len() - 1] {
        let next = match win_open_at(dir, comp, true, false) {
            Ok(h) => h,
            Err(e) => {
                // SAFETY: `dir` is a handle this function opened.
                unsafe { CloseHandle(dir) };
                return Err(e);
            }
        };
        // SAFETY: closing the handle this step walked away from.
        unsafe { CloseHandle(dir) };
        dir = next;
    }
    Ok((dir, leaf))
}

#[cfg(windows)]
fn open_beneath(root: &str, relative: &str) -> Result<VeilFsFile, String> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::CloseHandle;

    let (dir, leaf) = win_walk_to_parent(root, relative)?;
    let handle = win_open_at(dir, &leaf, false, false);
    // SAFETY: `dir` is open and finished with.
    unsafe { CloseHandle(dir) };
    let handle = handle?;
    // SAFETY: `handle` is a fresh file handle this module owns.
    let file = unsafe { std::fs::File::from_raw_handle(handle as *mut _) };
    let len = file
        .metadata()
        .map_err(|e| format!("cannot stat the opened file: {e}"))?
        .len();
    Ok(VeilFsFile { file, len })
}

#[cfg(windows)]
fn create_beneath(root: &str, relative: &str) -> Result<VeilFsFile, String> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::CloseHandle;

    let (dir, leaf) = win_walk_to_parent(root, relative)?;
    let handle = win_open_at(dir, &leaf, false, true);
    // SAFETY: `dir` is open and finished with.
    unsafe { CloseHandle(dir) };
    let handle = handle?;
    // SAFETY: `handle` is a fresh file handle this module owns.
    let file = unsafe { std::fs::File::from_raw_handle(handle as *mut _) };
    Ok(VeilFsFile { file, len: 0 })
}

#[cfg(windows)]
fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
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
            // O_NONBLOCK is not about the reads: on a regular file it changes
            // nothing. It is about the OPEN. Opening a FIFO with no writer
            // blocks in `open` itself — before the fstat below ever runs — so
            // a named pipe sitting in a granted folder held the calling thread
            // for as long as nobody wrote to it. The type check below promised
            // to refuse "something that blocks forever" and could not be
            // reached to do it (report24 V24-FS-01).
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
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
    // already refused a symlink; this refuses the rest. Reachable for a FIFO
    // only because the open above does not block — the two work as a pair.
    if widen(st.st_mode) & widen(libc::S_IFMT) != widen(libc::S_IFREG) {
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

    let components = split_components(relative)?;

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
/// Widen a mode word to `u32`, because it is not one width everywhere.
///
/// `st_mode` and the `S_IF*` constants are `u16` on macOS, `u32` on Linux —
/// and on 32-bit Android the field is `u32` while the constants are `u16`.
/// Comparing them directly therefore compiles on the machine this was written
/// on, and on the machines CI checks, and fails to compile for a phone: it did
/// exactly that in 0.11.24, on `armv7-linux-androideabi`, and nothing before
/// the tag had asked that target a question. Both sides go through here so the
/// comparison has one width on every target, and through `Into` rather than
/// `as` so that a widening cannot quietly become a truncation.
#[cfg(unix)]
fn widen(value: impl Into<u32>) -> u32 {
    value.into()
}

#[cfg(unix)]
fn component_is_symlink(dir: c_int, name: &CStr) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open directory descriptor, `name` is NUL-terminated,
    // `st` is writable.
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    rc == 0 && (widen(st.st_mode) & widen(libc::S_IFMT)) == widen(libc::S_IFLNK)
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, relative);
        unsafe { set_err(err_out, "veil_fs_create_beneath is POSIX-only") };
        std::ptr::null_mut()
    }

    #[cfg(any(unix, windows))]
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, offset, buf, len);
        unsafe { set_err(err_out, "veil_fs_write is POSIX-only") };
        -1
    }

    #[cfg(any(unix, windows))]
    {
        if handle.is_null() || buf.is_null() {
            unsafe { set_err(err_out, "null handle or buffer") };
            return -1;
        }
        // SAFETY: the caller guarantees `handle` is live and unclosed.
        let file = unsafe { &*handle };
        // SAFETY: `buf` is readable for `len` bytes per the contract above.
        let src = unsafe { std::slice::from_raw_parts(buf, len) };
        match write_at(file, offset, src) {
            Ok(n) => n as isize,
            Err(e) => {
                unsafe { set_err(err_out, &format!("write failed: {e}")) };
                -1
            }
        }
    }
}

/// Ask the operating system to put what was written on the DISK. Returns true,
/// or false with `*err_out` set.
///
/// `veil_fs_write` is a positional write: it reaches the kernel, and the kernel
/// decides when it reaches the platter. That distinction is the whole of this
/// function. A downloader writes a scratch file, flushes it and renames it over
/// the real name — and without a barrier between the writes and the rename, a
/// power loss can leave the new NAME pointing at a file whose contents were
/// never written, which is the one outcome the rename dance exists to prevent.
///
/// The Dart sink this replaced called `RandomAccessFile.flush`, which does the
/// same thing; when the writes moved to descriptors the barrier was quietly
/// dropped and the flush became a no-op that still looked like one
/// (report24 XV24-04).
///
/// # Safety
/// `handle` must come from [`veil_fs_create_beneath`] or
/// [`veil_fs_open_beneath`] and not have been closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_fs_sync(
    handle: *mut VeilFsFile,
    err_out: *mut *mut c_char,
) -> bool {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = handle;
        unsafe { set_err(err_out, "veil_fs_sync is POSIX-only") };
        false
    }

    #[cfg(any(unix, windows))]
    {
        if handle.is_null() {
            unsafe { set_err(err_out, "null handle") };
            return false;
        }
        // SAFETY: the caller guarantees `handle` is live and unclosed.
        let file = unsafe { &*handle };
        match sync_file(file) {
            Ok(()) => true,
            Err(e) => {
                unsafe { set_err(err_out, &format!("sync failed: {e}")) };
                false
            }
        }
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, offset, buf, len);
        unsafe { set_err(err_out, "veil_fs_read is POSIX-only") };
        -1
    }

    #[cfg(any(unix, windows))]
    {
        if handle.is_null() || buf.is_null() {
            unsafe { set_err(err_out, "null handle or buffer") };
            return -1;
        }
        // SAFETY: the caller guarantees `handle` is live and unclosed.
        let file = unsafe { &*handle };
        // SAFETY: `buf` is writable for `len` bytes per the contract above.
        let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        match read_at(file, offset, out) {
            Ok(n) => n as isize,
            Err(e) => {
                unsafe { set_err(err_out, &format!("read failed: {e}")) };
                -1
            }
        }
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

    /// An offset this platform cannot express is refused, not wrapped.
    ///
    /// On a 32-bit Android `off_t` is 32 bits, and `offset as off_t` turns
    /// 4 GiB + 5 into 5: a read that SUCCEEDS, holding somebody else's bytes.
    /// The conversion is checked instead, and this asserts the refusal BY ITS
    /// WORDS — a wrapping cast would fail here too, but with the system's
    /// EINVAL, and would leave the silent wrap in place on the one platform
    /// where it can actually happen.
    #[test]
    fn an_offset_this_platform_cannot_express_is_refused() {
        let root = scratch();
        write(&root.join("f.txt"), b"hello");
        let file = open_beneath(root.to_str().unwrap(), "f.txt").expect("open");

        let mut out = [0u8; 4];
        let err = read_at(&file, u64::MAX, &mut out).expect_err("must refuse");
        assert!(
            err.to_string().contains("beyond what this platform"),
            "refused for the wrong reason: {err}"
        );

        // The control, so the refusal above is about the offset and not about
        // the file: the same call at a reachable offset reads.
        assert_eq!(read_at(&file, 1, &mut out).expect("read"), 4);
        assert_eq!(&out, b"ello");

        std::fs::remove_dir_all(&root).ok();
    }

    /// A FIFO in the folder must be REFUSED, and refused quickly.
    ///
    /// Not the same test as the directory case below: a directory fails the
    /// type check, while a FIFO with no writer never reaches it — `open`
    /// blocks in the kernel until somebody opens the other end. Bounded here
    /// on purpose, because the failure mode of this defect is a thread that
    /// never comes back, and a test that simply calls the function would hang
    /// the suite rather than fail it (report24 V24-FS-01).
    #[test]
    fn a_fifo_is_refused_without_waiting_for_a_writer() {
        let root = scratch();
        let path = root.join("pipe");
        let c_path = CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` is NUL-terminated and names a path in a scratch dir.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "could not create the fifo: {}", last_error());

        let (tx, rx) = std::sync::mpsc::channel();
        let root_str = root.to_str().unwrap().to_owned();
        std::thread::spawn(move || {
            let _ = tx.send(open_beneath(&root_str, "pipe").is_err());
        });

        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(refused) => assert!(refused, "a fifo is not a file to send"),
            Err(_) => panic!(
                "open_beneath blocked on a fifo with no writer — the type \
                 check cannot refuse what the open never returns from"
            ),
        }
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// A directory nobody else in this run will get. Same reason as the POSIX
    /// side: these run in parallel threads of one process.
    fn scratch() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "veil-fs-beneath-win-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn read_all(file: &VeilFsFile) -> Vec<u8> {
        let mut out = vec![0u8; file.len as usize];
        let n = read_at(file, 0, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// A JUNCTION, which is what a symlink to a directory is on this platform
    /// that an ordinary user can actually create — `mklink /D` needs the
    /// developer mode or an elevated shell, `mklink /J` does not. It is also
    /// the shape that matters: a reparse point under a granted folder.
    fn junction(link: &std::path::Path, target: &std::path::Path) -> bool {
        std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// The ordinary case, so every refusal below means something.
    #[test]
    fn a_real_file_beneath_the_root_opens_and_reads() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/f.txt"), b"hello").unwrap();

        let file = open_beneath(root.to_str().unwrap(), "sub/f.txt").expect("open");
        assert_eq!(file.len, 5);
        assert_eq!(read_all(&file), b"hello");
        drop(file);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A reparse point on the way is REFUSED, not walked through.
    ///
    /// This is the whole Windows claim. `OBJ_DONT_REPARSE` is what makes
    /// `NtCreateFile` fail here instead of resolving the junction, and without
    /// it the walk would leave the granted folder exactly as a symlink walk
    /// does on POSIX.
    #[test]
    fn a_junction_component_is_refused() {
        let root = scratch();
        let outside = scratch();
        std::fs::write(outside.join("f.txt"), b"not yours").unwrap();
        if !junction(&root.join("link"), &outside) {
            // Nothing to say if the host would not make one; a silent pass
            // would be worse than saying so.
            eprintln!("SKIP: mklink /J unavailable on this host");
            return;
        }

        let err = open_beneath(root.to_str().unwrap(), "link/f.txt").unwrap_err();
        assert!(
            err.contains("reparse point"),
            "a junction must be refused as one: {err}"
        );
        // CONTROL: the ordinary path DOES walk through it, which is the gap.
        assert_eq!(
            std::fs::read(root.join("link/f.txt")).unwrap(),
            b"not yours",
            "if the plain read also refused, this test would prove nothing"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// `..` is refused rather than resolved, as on POSIX.
    #[test]
    fn a_parent_component_is_refused() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("f.txt"), b"inside").unwrap();
        let err = open_beneath(root.to_str().unwrap(), "sub/../f.txt").unwrap_err();
        assert!(err.contains(".."), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A backslash is a separator here too, so it cannot hide a component.
    #[test]
    fn a_backslash_separates_components_as_well() {
        let root = scratch();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/f.txt"), b"hello").unwrap();
        let file = open_beneath(root.to_str().unwrap(), r"sub\f.txt").expect("open");
        assert_eq!(read_all(&file), b"hello");
        drop(file);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Creating: the ordinary case, and then the two refusals.
    #[test]
    fn a_new_file_is_created_and_an_existing_name_is_refused() {
        let root = scratch();
        let file = create_beneath(root.to_str().unwrap(), "new.bin").expect("create");
        assert_eq!(write_at(&file, 0, b"written").unwrap(), 7);
        drop(file);
        assert_eq!(std::fs::read(root.join("new.bin")).unwrap(), b"written");

        let err = create_beneath(root.to_str().unwrap(), "new.bin").unwrap_err();
        assert!(err.contains("cannot open"), "{err}");
        assert_eq!(
            std::fs::read(root.join("new.bin")).unwrap(),
            b"written",
            "the existing file was truncated"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// THE POINT OF THE WALK, and on this platform the OS states it first.
    ///
    /// The POSIX twin of this test renames the directory out from under the
    /// open handle and checks that the read is unaffected. Windows does not
    /// allow the rename at all while a file inside is open — it answers
    /// ACCESS_DENIED — so the substitution the finding describes cannot even
    /// be staged here. That is a stronger guarantee than POSIX gives, not a
    /// weaker one, and this test asserts what actually happens rather than
    /// carrying over a scenario the platform forbids.
    ///
    /// Both halves matter: the rename must fail AND the handle must keep
    /// answering with the authorized bytes. A refusal alone would also be
    /// satisfied by a handle that had died.
    #[test]
    fn an_open_handle_blocks_the_swap_outright() {
        let root = scratch();
        std::fs::create_dir(root.join("a")).unwrap();
        std::fs::write(root.join("a/f.txt"), b"authorized").unwrap();
        std::fs::create_dir(root.join("evil")).unwrap();
        std::fs::write(root.join("evil/f.txt"), b"substituted").unwrap();

        let file = open_beneath(root.to_str().unwrap(), "a/f.txt").expect("open");
        assert!(
            std::fs::rename(root.join("a"), root.join("gone")).is_err(),
            "the directory was renamed while a file inside it was open"
        );
        assert_eq!(
            read_all(&file),
            b"authorized",
            "the handle stopped answering, so the refusal above proves nothing"
        );
        drop(file);
        // And once the handle is gone the rename is ordinary again — the
        // control for the assertion above, which would otherwise pass on a
        // filesystem that refuses every rename.
        assert!(std::fs::rename(root.join("a"), root.join("gone")).is_ok());
        std::fs::remove_dir_all(&root).ok();
    }
}
