//! Recoverable replacement under a single pinned parent.
//!
//! The old entry is moved to a permanent recovery name, never unlinked. The
//! incoming entry is installed with destination exclusion. An intent reaches
//! the disk BEFORE the first move; recovery runs before a folder scan can
//! mistake a temporarily absent target for a user deletion. A directory lock
//! excludes another publisher/recovery in this directory, including a second
//! process. External editors need not participate in that lock.
//!
//! This protects process-interruption boundaries. Unix also syncs the parent
//! at each namespace transition. Windows flushes files but does not claim a
//! portable directory-fsync/power-loss guarantee. Unreadable or ambiguous
//! recovery state is refused, never converted into an ordinary empty scan.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Mutex, MutexGuard};
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use super::move_entry::PreparedMove;

const MAGIC: &[u8; 8] = b"XVPUB01\0";
const SETTLED_OFFSET: u64 = 8;
const MAX_INTENT_BYTES: usize = 1036;
#[cfg(windows)]
const LOCK_NAME: &str = ".xveil-sync.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Version {
    pub size: u64,
    pub modified_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    Published(Version),
    LocalChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    IntentDurable,
    PreviousMoved,
    BeforeInstall,
    IncomingInstalled,
    Settled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DiscardStage {
    BeforeCapture,
    Captured,
    Removed,
}

/// This and PreparedMove share one pinned OS directory, not separate walks.
struct Parent(File);

/// A root-wide admission shared by publication, recovery and the host scan.
/// Holding it across recovery AND enumeration prevents another publisher's
/// temporary missing name from being interpreted as a user deletion.
pub(super) struct FolderSession {
    root: Parent,
    _lock: File,
    operations: Mutex<()>,
}

impl FolderSession {
    pub(super) fn open(root: &str) -> Result<Self, String> {
        let root = Parent::open(root, ".xveil-anchor")?;
        let lock = root.lock()?;
        Ok(Self {
            root,
            _lock: lock,
            operations: Mutex::new(()),
        })
    }

    fn operation(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.operations.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => "folder publication is busy".to_owned(),
            std::sync::TryLockError::Poisoned(_) => "folder admission failed".to_owned(),
        })
    }

    pub(super) fn publish(
        &self,
        target: &str,
        incoming: &str,
        expected: Option<Version>,
    ) -> Result<Outcome, String> {
        self.publish_with_hook(target, incoming, expected, |_| Ok(()))
    }

    /// Create only a protocol incoming file, beneath this pinned root. Missing
    /// parents are made descriptor-relative and reopened without following
    /// links. The caller writes/flushes/closes it before publication; obtaining
    /// this file never authorizes an overwrite of a user entry.
    pub(super) fn create_incoming(&self, incoming: &str) -> Result<File, String> {
        let _operation = self.operation()?;
        let parts = super::split_components(incoming)?;
        let name = parts.last().ok_or("missing incoming")?;
        stem(name, ".incoming")?; // Validate before creating any directory.
        self.parent_with_creation(incoming, true)?
            .required(name, true, true)
    }

    /// Read a protocol copy or its intent through this root, never a user
    /// target chosen from intent contents. The returned descriptor survives
    /// releasing the admission; a chooser must not hold the folder lock.
    pub(super) fn open_saved(&self, relative: &str) -> Result<Option<File>, String> {
        let _operation = self.operation()?;
        let parts = super::split_components(relative)?;
        let name = parts.last().ok_or("missing saved entry")?;
        if ![".previous", ".incoming", ".intent"]
            .iter()
            .any(|suffix| stem(name, suffix).is_ok())
        {
            return Err("invalid saved entry".to_owned());
        }
        self.parent(relative)?.file(name, false, false)
    }

    /// Explicit removal only: the caller holds the selected saved descriptor
    /// across confirmation. Unsettled/corrupt journals and orphan previous
    /// copies require recovery, not deletion. Capture with exclusion before
    /// checking identity, so a namespace replacement is preserved too.
    pub(super) fn discard_saved(
        &self,
        relative: &str,
        selected: &File,
        stamp: (u64, std::time::SystemTime),
        quarantine: &str,
    ) -> Result<bool, String> {
        self.discard_saved_with_hook(relative, selected, stamp, quarantine, |_| Ok(()))
    }

    fn discard_saved_with_hook(
        &self,
        relative: &str,
        selected: &File,
        stamp: (u64, std::time::SystemTime),
        quarantine: &str,
        mut hook: impl FnMut(DiscardStage) -> Result<(), String>,
    ) -> Result<bool, String> {
        let _operation = self.operation()?;
        let parts = super::split_components(relative)?;
        let name = parts.last().ok_or("missing saved entry")?;
        let (stem, previous) = if let Ok(stem) = stem(name, ".previous") {
            (stem, true)
        } else {
            (stem(name, ".incoming")?, false)
        };
        let destination = super::move_entry::destination_leaf(relative, quarantine)?;
        let spare_stem = self::stem(&destination, ".incoming")?;
        if spare_stem == stem {
            return Err("discard capture must have a fresh name".to_owned());
        }
        let parent = self.parent(relative)?;
        for suffix in [".intent", ".previous", ".incoming"] {
            if parent.entry_exists(&format!("{spare_stem}{suffix}"))? {
                return Err("discard capture is occupied".to_owned());
            }
        }
        let intent_name = format!("{stem}.intent");
        let mut journal = parent.file(&intent_name, false, false)?;
        if let Some(file) = journal.as_mut() {
            if !Intent::read(file)?.settled {
                return Err("saved copy still requires recovery".to_owned());
            }
        } else if previous {
            return Err("previous copy has no recovery record".to_owned());
        }
        let matches = |file: &File| -> Result<bool, String> {
            let metadata = file.metadata().map_err(io_error)?;
            Ok(metadata.is_file()
                && same_object(selected, file)?
                && (metadata.len(), metadata.modified().map_err(io_error)?) == stamp)
        };
        if !matches(selected)? {
            return Ok(false);
        }
        match parent.file(name, false, false)? {
            Some(file) if matches(&file)? => {}
            _ => return Ok(false),
        }
        hook(DiscardStage::BeforeCapture)?;
        if !parent.move_entry(name, &destination)? {
            return Err("discard capture is occupied".to_owned());
        }
        parent.sync()?;
        hook(DiscardStage::Captured)?;
        let captured = parent.required(&destination, false, false);
        let matching = captured.as_ref().map_err(|e| e.clone()).and_then(matches);
        if !matches!(matching, Ok(true)) {
            // A new source entry or a late edit wins. Restore only into an
            // empty name; otherwise keep the capture visible as an orphan.
            parent.move_entry(&destination, name)?;
            parent.sync()?;
            return matching.map(|_| false);
        }
        let captured = captured?;
        parent.remove_file(&destination, &captured)?;
        parent.sync()?;
        hook(DiscardStage::Removed)?;
        // Settled records no longer authorize recovery. Remove metadata only
        // after its last copy is gone. A crash at any earlier step leaves a
        // harmless settled record and/or an exportable incoming capture.
        if let Some(journal) = journal
            && !parent.entry_exists(&format!("{stem}.previous"))?
            && !parent.entry_exists(&format!("{stem}.incoming"))?
        {
            parent.remove_file(&intent_name, &journal)?;
            parent.sync()?;
        }
        Ok(true)
    }

    fn publish_with_hook(
        &self,
        target: &str,
        incoming: &str,
        expected: Option<Version>,
        mut hook: impl FnMut(Stage) -> Result<(), String>,
    ) -> Result<Outcome, String> {
        let _operation = self.operation()?;
        // One admission remains held for the entire transaction. Reopening
        // a named root between steps would lose both pinning and exclusion.
        super::move_entry::destination_leaf(incoming, target)?;
        let target_parts = super::split_components(target)?;
        let target_leaf = target_parts.last().ok_or("missing target")?;
        let incoming_parts = super::split_components(incoming)?;
        let incoming_leaf = incoming_parts.last().ok_or("missing incoming")?;
        let stem = stem(incoming_leaf, ".incoming")?;
        let parent = self.parent(target)?;
        publish_locked(
            &parent,
            target_leaf,
            incoming_leaf,
            &stem,
            expected,
            &mut hook,
        )
    }

    pub(super) fn recover(&self, relative_intent: &str) -> Result<bool, String> {
        let _operation = self.operation()?;
        let parts = super::split_components(relative_intent)?;
        let name = parts.last().ok_or("missing intent")?;
        let stem = stem(name, ".intent")?;
        let parent = self.parent(relative_intent)?;
        let mut journal = parent.required(name, false, true)?;
        let intent = Intent::read(&mut journal)?;
        if intent.settled {
            return Ok(false);
        }
        recover_locked(&parent, &stem, &intent, &mut journal)?;
        Ok(true)
    }

    /// The scan still enumerates by the host's pathname. Refuse a renamed or
    /// substituted root before accepting that enumeration as a complete scan.
    /// This is a consistency check, not an atomic filesystem snapshot.
    pub(super) fn matches_root(&self, path: &str) -> Result<bool, String> {
        let other = Parent::open(path, ".xveil-anchor")?;
        same_object(&self.root.0, &other.0)
    }

    fn parent(&self, relative: &str) -> Result<Parent, String> {
        self.parent_with_creation(relative, false)
    }

    fn parent_with_creation(&self, relative: &str, create: bool) -> Result<Parent, String> {
        let parts = super::split_components(relative)?;
        #[cfg(windows)]
        if parts.iter().any(|part| part.contains(':')) {
            return Err("drive or alternate stream in folder path".to_owned());
        }
        let mut directory = self.root.0.try_clone().map_err(io_error)?;
        for name in &parts[..parts.len() - 1] {
            #[cfg(unix)]
            {
                let name = std::ffi::CString::new(*name).map_err(|_| "NUL in directory")?;
                if create {
                    // EEXIST is only a candidate: the no-follow directory
                    // open below must still accept the actual object.
                    let result =
                        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
                    if result != 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::AlreadyExists {
                            return Err(io_error(error));
                        }
                    }
                }
                // SAFETY: a relative component, held directory and no-follow
                // flags keep each step beneath the already opened root.
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io_error(std::io::Error::last_os_error()));
                }
                // SAFETY: openat transfers one fresh descriptor.
                directory = unsafe { File::from_raw_fd(fd) };
            }
            #[cfg(windows)]
            {
                let handle = super::win_open_at(directory.as_raw_handle(), name, true, false)
                    .or_else(|error| {
                        if !create {
                            return Err(error);
                        }
                        // A concurrent creator can win the exclusive create.
                        // Reopening still uses OBJ_DONT_REPARSE and directory
                        // type checking; an error never selects a path fallback.
                        super::win_open_at(directory.as_raw_handle(), name, true, true).or_else(
                            |_| super::win_open_at(directory.as_raw_handle(), name, true, false),
                        )
                    })?;
                // SAFETY: win_open_at transfers one fresh handle.
                directory = unsafe { File::from_raw_handle(handle) };
            }
        }
        Ok(Parent(directory))
    }
}

fn same_object(a: &File, b: &File) -> Result<bool, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = a.metadata().map_err(io_error)?;
        let b = b.metadata().map_err(io_error)?;
        Ok(a.dev() == b.dev() && a.ino() == b.ino())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let id = |file: &File| {
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: the held file and writable info outlive the call.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            Ok((
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ))
        };
        Ok(id(a)? == id(b)?)
    }
}

impl Parent {
    fn open(root: &str, relative: &str) -> Result<Self, String> {
        #[cfg(unix)]
        {
            let (fd, _) = super::walk_to_parent(root, relative)?;
            // SAFETY: the walk transfers one fresh descriptor.
            Ok(Self(unsafe { File::from_raw_fd(fd) }))
        }
        #[cfg(windows)]
        {
            let (handle, _) = super::win_walk_to_parent(root, relative)?;
            // SAFETY: the walk transfers one fresh handle.
            Ok(Self(unsafe { File::from_raw_handle(handle) }))
        }
    }

    fn file(&self, name: &str, create: bool, writable: bool) -> Result<Option<File>, String> {
        leaf(name)?;
        #[cfg(unix)]
        let file = {
            let name = std::ffi::CString::new(name).map_err(|_| "NUL in name")?;
            let flags = libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if create || writable {
                    libc::O_RDWR
                } else {
                    libc::O_RDONLY
                }
                | if create {
                    libc::O_CREAT | libc::O_EXCL
                } else {
                    0
                };
            // SAFETY: parent and the C name outlive this descriptor-relative open.
            let fd = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags, 0o600) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if !create && error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(format!("publication open refused: {error}"));
            }
            // SAFETY: openat transfers one fresh descriptor.
            unsafe { File::from_raw_fd(fd) }
        };
        #[cfg(windows)]
        let file = {
            use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
            let access = if create {
                FILE_GENERIC_READ
            } else if writable {
                FILE_GENERIC_WRITE
            } else {
                0
            };
            let Some(handle) = super::win_try_open_at_with_options(
                self.0.as_raw_handle(),
                name,
                false,
                create,
                access,
                name != LOCK_NAME,
            )?
            else {
                return Ok(None);
            };
            // SAFETY: the NT open transfers one fresh handle.
            unsafe { File::from_raw_handle(handle) }
        };
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err("publication entry is not a regular file".to_owned());
        }
        Ok(Some(file))
    }

    fn required(&self, name: &str, create: bool, writable: bool) -> Result<File, String> {
        self.file(name, create, writable)?
            .ok_or_else(|| "publication entry is absent".to_owned())
    }

    fn lock(&self) -> Result<File, String> {
        // Lock the pinned directory itself on Unix: unlinking/replacing a
        // separate lockfile must not create a second independent lock.
        #[cfg(unix)]
        let file = self.0.try_clone().map_err(io_error)?;
        #[cfg(windows)]
        // No truncation/adoption of a link. A simultaneous creator may win;
        // refusing this attempt is safe and leaves the other owner untouched.
        // The opened Windows lockfile denies DELETE sharing while held.
        let file = match self.file(LOCK_NAME, false, true)? {
            Some(file) => file,
            None => self.required(LOCK_NAME, true, true)?,
        };
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => "folder publication is busy".to_owned(),
            std::fs::TryLockError::Error(error) => io_error(error),
        })?;
        Ok(file)
    }

    fn move_entry(&self, from: &str, to: &str) -> Result<bool, String> {
        PreparedMove::in_parent(&self.0, from, to)?.execute()
    }

    fn sync(&self) -> Result<(), String> {
        #[cfg(unix)]
        self.0.sync_all().map_err(io_error)?;
        Ok(())
    }

    /// Delete only a protocol entry inside this pinned parent. Unix unlinkat
    /// never follows a leaf link; Windows marks the opened no-reparse object.
    /// The random capture namespace is reserved to this admitted operation.
    /// This is explicit user deletion, not an immutable snapshot against an
    /// external process writing through an already open file descriptor.
    fn remove_file(&self, name: &str, selected: &File) -> Result<(), String> {
        leaf(name)?;
        #[cfg(unix)]
        {
            let file = self.required(name, false, false)?;
            if !same_object(&file, selected)? {
                return Err("discard entry changed".to_owned());
            }
            let name = std::ffi::CString::new(name).map_err(|_| "NUL in name")?;
            // SAFETY: pinned directory and leaf C name outlive the syscall.
            if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Wdk::Storage::FileSystem::{
                FILE_DISPOSITION_INFORMATION, FileDispositionInformation, NtSetInformationFile,
            };
            use windows_sys::Win32::Foundation::STATUS_SUCCESS;
            use windows_sys::Win32::Storage::FileSystem::DELETE;
            use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
            let handle =
                super::win_open_at_with_access(self.0.as_raw_handle(), name, false, false, DELETE)?;
            // SAFETY: the NT open transfers one owned no-reparse file handle.
            let file = unsafe { File::from_raw_handle(handle) };
            if !same_object(&file, selected)? {
                return Err("discard entry changed".to_owned());
            }
            let mut disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: 1 };
            let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
            // SAFETY: opened DELETE handle and both fixed-size buffers remain live.
            let status = unsafe {
                NtSetInformationFile(
                    file.as_raw_handle(),
                    &mut iosb,
                    (&mut disposition as *mut FILE_DISPOSITION_INFORMATION).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                    FileDispositionInformation,
                )
            };
            if status != STATUS_SUCCESS {
                return Err(format!("discard refused (NTSTATUS {status:#x})"));
            }
        }
        Ok(())
    }

    fn version(&self, name: &str) -> Result<Option<Version>, String> {
        self.file(name, false, false)?
            .map(|file| version(&file))
            .transpose()
    }

    /// Presence, without following a leaf link and without requiring a regular
    /// file. Recovery may have to put back a directory/link substituted by an
    /// editor immediately before the move. A newer occupied name always wins.
    fn entry_exists(&self, name: &str) -> Result<bool, String> {
        leaf(name)?;
        #[cfg(unix)]
        {
            let name = std::ffi::CString::new(name).map_err(|_| "NUL in name")?;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let mut stat: libc::stat64 = unsafe { std::mem::zeroed() };
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: the pinned parent, valid C name and writable stat buffer
            // outlive this no-follow query. The 64-bit variant avoids EOVERFLOW
            // for a large file on 32-bit Android.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let rc = unsafe {
                libc::fstatat64(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let rc = unsafe {
                libc::fstatat(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }
            Err(io_error(error))
        }
        #[cfg(windows)]
        {
            use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
            use windows_sys::Wdk::Storage::FileSystem::{
                FILE_NETWORK_OPEN_INFORMATION, NtQueryFullAttributesFile,
            };
            use windows_sys::Win32::Foundation::{STATUS_SUCCESS, UNICODE_STRING};
            let len =
                super::nt_name_byte_len(name.encode_utf16().count()).ok_or("filename too long")?;
            let mut wide: Vec<u16> = name.encode_utf16().collect();
            let mut unicode = UNICODE_STRING {
                Length: len,
                MaximumLength: len,
                Buffer: wide.as_mut_ptr(),
            };
            let attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: self.0.as_raw_handle(),
                ObjectName: &mut unicode,
                Attributes: super::OBJ_CASE_INSENSITIVE | super::OBJ_DONT_REPARSE,
                SecurityDescriptor: std::ptr::null_mut(),
                SecurityQualityOfService: std::ptr::null_mut(),
            };
            let mut info: FILE_NETWORK_OPEN_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: all buffers and the held parent live through this query.
            let status = unsafe { NtQueryFullAttributesFile(&attrs, &mut info) };
            const NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
            const REPARSE_ENCOUNTERED: i32 = 0xC000_050B_u32 as i32;
            match status {
                STATUS_SUCCESS | REPARSE_ENCOUNTERED => Ok(true),
                NAME_NOT_FOUND => Ok(false),
                _ => Err(format!(
                    "publication presence query refused (NTSTATUS {status:#x})"
                )),
            }
        }
    }
}

fn io_error(error: std::io::Error) -> String {
    format!("publication IO failed: {error}")
}

fn leaf(name: &str) -> Result<(), String> {
    let parts = super::split_components(name)?;
    if parts.len() != 1 || parts[0] != name {
        return Err("publication requires a single relative filename".to_owned());
    }
    #[cfg(windows)]
    if name.contains(':') {
        return Err("publication filename must not name an alternate stream".to_owned());
    }
    Ok(())
}

fn version(file: &File) -> Result<Version, String> {
    let metadata = file.metadata().map_err(io_error)?;
    version_metadata(&metadata)
}

pub(super) fn version_metadata(metadata: &std::fs::Metadata) -> Result<Version, String> {
    if !metadata.is_file() {
        return Err("publication source is not regular".to_owned());
    }
    let modified = metadata.modified().map_err(io_error)?;
    let millis = match modified.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_millis()).map_err(|_| "mtime overflow")?,
        Err(error) => -i128::try_from(error.duration().as_nanos().div_ceil(1_000_000))
            .map_err(|_| "mtime overflow")?,
    };
    Ok(Version {
        size: metadata.len(),
        modified_ms: i64::try_from(millis).map_err(|_| "mtime overflow")?,
    })
}

/// Only opaque 128-bit names from the host's secure RNG enter this namespace.
fn stem(name: &str, suffix: &str) -> Result<String, String> {
    leaf(name)?;
    let value = name
        .strip_prefix(".xveil-")
        .and_then(|s| s.strip_suffix(suffix))
        .ok_or("invalid publication name")?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid publication nonce".to_owned());
    }
    Ok(format!(".xveil-{value}"))
}

struct Intent {
    target: String,
    was_present: bool,
    settled: bool,
}

impl Intent {
    fn encode(&self) -> Result<Vec<u8>, String> {
        leaf(&self.target)?;
        if self.target.starts_with('.') || self.target.len() > MAX_INTENT_BYTES - 12 {
            return Err("unsupported publication target".to_owned());
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend([u8::from(self.settled), u8::from(self.was_present)]);
        bytes.extend(
            u16::try_from(self.target.len())
                .map_err(|_| "target too long")?
                .to_le_bytes(),
        );
        bytes.extend(self.target.as_bytes());
        Ok(bytes)
    }

    fn read(file: &mut File) -> Result<Self, String> {
        let mut bytes = Vec::new();
        file.take((MAX_INTENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() < 12
            || bytes.len() > MAX_INTENT_BYTES
            || &bytes[..8] != MAGIC
            || bytes[8] > 1
            || bytes[9] > 1
            || bytes.len() != 12 + usize::from(u16::from_le_bytes([bytes[10], bytes[11]]))
        {
            return Err("unreadable publication intent; manual recovery required".to_owned());
        }
        let intent = Self {
            target: String::from_utf8(bytes[12..].to_vec())
                .map_err(|_| "invalid target encoding")?,
            was_present: bytes[9] == 1,
            settled: bytes[8] == 1,
        };
        // Apply exactly the same namespace policy on recovery as on creation.
        intent.encode()?;
        Ok(intent)
    }

    fn settle(file: &mut File) -> Result<(), String> {
        file.seek(SeekFrom::Start(SETTLED_OFFSET))
            .map_err(io_error)?;
        file.write_all(&[1]).map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }
}

#[cfg(test)]
fn publish(
    root: &str,
    target: &str,
    incoming: &str,
    expected: Option<Version>,
) -> Result<Outcome, String> {
    FolderSession::open(root)?.publish(target, incoming, expected)
}

#[cfg(test)]
fn publish_with_hook(
    root: &str,
    target: &str,
    incoming: &str,
    expected: Option<Version>,
    hook: impl FnMut(Stage) -> Result<(), String>,
) -> Result<Outcome, String> {
    FolderSession::open(root)?.publish_with_hook(target, incoming, expected, hook)
}

fn publish_locked(
    parent: &Parent,
    target_leaf: &str,
    incoming_leaf: &str,
    stem: &str,
    expected: Option<Version>,
    mut hook: impl FnMut(Stage) -> Result<(), String>,
) -> Result<Outcome, String> {
    if parent.version(target_leaf)? != expected {
        return Ok(Outcome::LocalChanged);
    }
    let prepared = parent.required(incoming_leaf, false, true)?;
    let receipt = version(&prepared)?;
    // Flush even when a host forgot its own final flush; no namespace changes yet.
    prepared.sync_all().map_err(io_error)?;
    let intent = Intent {
        target: (*target_leaf).to_owned(),
        was_present: expected.is_some(),
        settled: false,
    };
    let bytes = intent.encode()?;
    let intent_name = format!("{stem}.intent");
    let previous_name = format!("{stem}.previous");
    let mut journal = parent.required(&intent_name, true, true)?;
    journal.write_all(&bytes).map_err(io_error)?;
    journal.sync_all().map_err(io_error)?;
    parent.sync()?;
    hook(Stage::IntentDurable)?;
    if expected.is_some() {
        if !parent.move_entry(target_leaf, &previous_name)? {
            // Never adopt or overwrite a pre-existing recovery copy.
            return Err("publication recovery name is occupied".to_owned());
        }
        parent.sync()?;
        hook(Stage::PreviousMoved)?;
        // The actual displaced object may differ from the pre-move stat.
        if !matches!(parent.version(&previous_name), Ok(actual) if actual == expected) {
            recover_locked(parent, stem, &intent, &mut journal)?;
            return Ok(Outcome::LocalChanged);
        }
    }
    hook(Stage::BeforeInstall)?;
    if !parent.move_entry(incoming_leaf, target_leaf)? {
        recover_locked(parent, stem, &intent, &mut journal)?;
        return Ok(Outcome::LocalChanged);
    }
    parent.sync()?;
    hook(Stage::IncomingInstalled)?;
    Intent::settle(&mut journal)?;
    hook(Stage::Settled)?;
    Ok(Outcome::Published(receipt))
}

/// Recover ONE intent discovered by the host BEFORE it scans ordinary files.
/// The host must not scan if this refuses. Successful recovery never deletes
/// bytes: a newer occupied target and all side copies are left intact.
#[cfg(test)]
fn recover(root: &str, relative_intent: &str) -> Result<bool, String> {
    FolderSession::open(root)?.recover(relative_intent)
}

fn recover_locked(
    parent: &Parent,
    stem: &str,
    intent: &Intent,
    journal: &mut File,
) -> Result<(), String> {
    if !parent.entry_exists(&intent.target)? {
        let previous = format!("{stem}.previous");
        if parent.entry_exists(&previous)? {
            // A newly appearing user file wins this name; the displaced bytes
            // remain in previous. Destination exclusion applies on recovery too.
            parent.move_entry(&previous, &intent.target)?;
        } else if intent.was_present {
            return Err(
                "target and recovery copy are both absent; manual recovery required".to_owned(),
            );
        }
    }
    parent.sync()?;
    Intent::settle(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const INCOMING: &str = ".xveil-0123456789abcdef0123456789abcdef.incoming";
    const INTENT: &str = ".xveil-0123456789abcdef0123456789abcdef.intent";
    const PREVIOUS: &str = ".xveil-0123456789abcdef0123456789abcdef.previous";
    const CHILD_ROOT: &str = "VEIL_FS_PUBLICATION_CRASH_QA_ROOT";
    const CHILD_STAGE: &str = "VEIL_FS_PUBLICATION_CRASH_QA_STAGE";
    const CHILD_TEST: &str =
        "fs_beneath::publication::tests::process_exit_at_every_transition_leaves_recoverable_files";

    fn child(root: &Path, stage: &str) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--test-threads=1"])
            .env(CHILD_ROOT, root)
            .env(CHILD_STAGE, stage)
            .output()
            .unwrap()
    }

    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "veil-publication-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn root(&self) -> &str {
            self.0.to_str().unwrap()
        }
        fn put(&self, name: &str, bytes: &[u8]) {
            std::fs::write(self.0.join(name), bytes).unwrap();
        }
        fn read(&self, name: &str) -> Vec<u8> {
            std::fs::read(self.0.join(name)).unwrap()
        }
        fn version(&self, name: &str) -> Version {
            version(&File::open(self.0.join(name)).unwrap()).unwrap()
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    const DISCARD: &str = ".xveil-abcdef0123456789abcdef0123456789.incoming";

    fn saved_stamp(file: &File) -> (u64, std::time::SystemTime) {
        let m = file.metadata().unwrap();
        (m.len(), m.modified().unwrap())
    }

    fn published_tree() -> Tree {
        let tree = Tree::new();
        tree.put("note.txt", b"previous bytes");
        tree.put(INCOMING, b"current bytes");
        let outcome = publish(
            tree.root(),
            "note.txt",
            INCOMING,
            Some(tree.version("note.txt")),
        )
        .unwrap();
        assert!(matches!(outcome, Outcome::Published(_)));
        tree
    }

    #[test]
    fn explicit_discard_removes_only_the_confirmed_completed_copy_and_last_intent() {
        let tree = published_tree();
        let session = FolderSession::open(tree.root()).unwrap();
        let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
        assert!(
            session
                .discard_saved(PREVIOUS, &selected, saved_stamp(&selected), DISCARD)
                .unwrap()
        );
        drop(selected); // Windows completes its delete after the final handle closes.
        assert_eq!(tree.read("note.txt"), b"current bytes");
        assert!(!tree.0.join(PREVIOUS).exists());
        assert!(!tree.0.join(INTENT).exists());
        assert!(!tree.0.join(DISCARD).exists());
    }

    #[test]
    fn explicit_discard_accepts_an_unpublished_incoming_orphan_only() {
        let tree = Tree::new();
        tree.put(INCOMING, b"partial bytes");
        tree.put(PREVIOUS, b"orphan previous");
        let session = FolderSession::open(tree.root()).unwrap();
        let previous = session.open_saved(PREVIOUS).unwrap().unwrap();
        assert!(
            session
                .discard_saved(PREVIOUS, &previous, saved_stamp(&previous), DISCARD)
                .is_err()
        );
        let incoming = session.open_saved(INCOMING).unwrap().unwrap();
        assert!(
            session
                .discard_saved(INCOMING, &incoming, saved_stamp(&incoming), DISCARD)
                .unwrap()
        );
        drop(incoming);
        assert!(!tree.0.join(INCOMING).exists());
        assert_eq!(tree.read(PREVIOUS), b"orphan previous");
    }

    #[test]
    fn explicit_discard_refuses_unsettled_and_corrupt_records_without_a_move() {
        let tree = published_tree();
        let session = FolderSession::open(tree.root()).unwrap();
        let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
        let mut bytes = tree.read(INTENT);
        bytes[8] = 0;
        for record in [bytes, b"corrupt".to_vec()] {
            tree.put(INTENT, &record);
            assert!(
                session
                    .discard_saved(PREVIOUS, &selected, saved_stamp(&selected), DISCARD)
                    .is_err()
            );
            assert_eq!(tree.read(PREVIOUS), b"previous bytes");
            assert!(!tree.0.join(DISCARD).exists());
        }
        assert_eq!(tree.read("note.txt"), b"current bytes");
    }

    #[test]
    fn explicit_discard_rejects_a_late_edit_and_a_replaced_selected_name() {
        let tree = published_tree();
        let session = FolderSession::open(tree.root()).unwrap();
        let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
        let stamp = saved_stamp(&selected);
        tree.put(PREVIOUS, b"edited after confirmation");
        assert!(
            !session
                .discard_saved(PREVIOUS, &selected, stamp, DISCARD)
                .unwrap()
        );
        std::fs::rename(tree.0.join(PREVIOUS), tree.0.join("kept.txt")).unwrap();
        tree.put(PREVIOUS, b"replacement");
        assert!(
            !session
                .discard_saved(PREVIOUS, &selected, saved_stamp(&selected), DISCARD)
                .unwrap()
        );
        assert_eq!(tree.read(PREVIOUS), b"replacement");
        assert_eq!(tree.read("kept.txt"), b"edited after confirmation");
    }

    #[test]
    fn discard_capture_preserves_a_namespace_race_instead_of_deleting_the_replacement() {
        let tree = published_tree();
        let session = FolderSession::open(tree.root()).unwrap();
        let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
        assert!(
            !session
                .discard_saved_with_hook(
                    PREVIOUS,
                    &selected,
                    saved_stamp(&selected),
                    DISCARD,
                    |stage| {
                        if stage == DiscardStage::BeforeCapture {
                            std::fs::rename(tree.0.join(PREVIOUS), tree.0.join("kept.txt"))
                                .unwrap();
                            tree.put(PREVIOUS, b"replacement at the last moment");
                        }
                        if stage == DiscardStage::Captured {
                            tree.put(PREVIOUS, b"new occupied source name");
                        }
                        Ok(())
                    }
                )
                .unwrap()
        );
        assert_eq!(tree.read(PREVIOUS), b"new occupied source name");
        assert_eq!(tree.read(DISCARD), b"replacement at the last moment");
        assert_eq!(tree.read("kept.txt"), b"previous bytes");
        assert_eq!(tree.read("note.txt"), b"current bytes");
    }

    #[test]
    fn discard_refuses_occupied_capture_or_another_parent_without_touching_bytes() {
        let tree = published_tree();
        let session = FolderSession::open(tree.root()).unwrap();
        let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
        let stamp = saved_stamp(&selected);
        tree.put(DISCARD, b"occupied");
        assert!(
            session
                .discard_saved(PREVIOUS, &selected, stamp, DISCARD)
                .is_err()
        );
        assert!(
            session
                .discard_saved(PREVIOUS, &selected, stamp, &format!("nested/{DISCARD}"))
                .is_err()
        );
        assert!(
            session
                .discard_saved("note.txt", &selected, stamp, DISCARD)
                .is_err()
        );
        assert_eq!(tree.read(DISCARD), b"occupied");
        assert_eq!(tree.read(PREVIOUS), b"previous bytes");
        assert_eq!(tree.read("note.txt"), b"current bytes");
    }

    #[test]
    fn discard_failure_after_capture_leaves_an_exportable_orphan() {
        let tree = published_tree();
        let session = FolderSession::open(tree.root()).unwrap();
        let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
        assert!(
            session
                .discard_saved_with_hook(
                    PREVIOUS,
                    &selected,
                    saved_stamp(&selected),
                    DISCARD,
                    |stage| {
                        if stage == DiscardStage::Captured {
                            Err("interrupted".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        let mut rescued = session.open_saved(DISCARD).unwrap().unwrap();
        let mut bytes = Vec::new();
        rescued.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"previous bytes");
        assert!(!session.recover(INTENT).unwrap());
        assert_eq!(tree.read("note.txt"), b"current bytes");
    }

    #[test]
    fn discard_keeps_the_record_until_its_other_copy_is_explicitly_removed() {
        let tree = published_tree();
        tree.put(INCOMING, b"another retained candidate");
        let session = FolderSession::open(tree.root()).unwrap();
        let previous = session.open_saved(PREVIOUS).unwrap().unwrap();
        assert!(
            session
                .discard_saved(PREVIOUS, &previous, saved_stamp(&previous), DISCARD)
                .unwrap()
        );
        drop(previous);
        assert!(tree.0.join(INTENT).exists());
        assert_eq!(tree.read(INCOMING), b"another retained candidate");
        let incoming = session.open_saved(INCOMING).unwrap().unwrap();
        assert!(
            session
                .discard_saved(INCOMING, &incoming, saved_stamp(&incoming), DISCARD)
                .unwrap()
        );
        drop(incoming);
        assert!(!tree.0.join(INTENT).exists());
        assert_eq!(tree.read("note.txt"), b"current bytes");
    }

    #[test]
    fn process_exit_during_discard_keeps_unremoved_bytes_available() {
        const STAGE: &str = "VEIL_FS_DISCARD_CRASH_QA_STAGE";
        if let Ok(root) = std::env::var(CHILD_ROOT) {
            let stage = std::env::var(STAGE).unwrap();
            let session = FolderSession::open(&root).unwrap();
            let selected = session.open_saved(PREVIOUS).unwrap().unwrap();
            session
                .discard_saved_with_hook(
                    PREVIOUS,
                    &selected,
                    saved_stamp(&selected),
                    DISCARD,
                    |at| {
                        let name = match at {
                            DiscardStage::BeforeCapture => "before",
                            DiscardStage::Captured => "captured",
                            DiscardStage::Removed => "removed",
                        };
                        if stage == name {
                            std::process::exit(79);
                        }
                        Ok(())
                    },
                )
                .unwrap();
            panic!("discard crash hook was not reached");
        }
        for stage in ["before", "captured", "removed"] {
            let tree = published_tree();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "fs_beneath::publication::tests::process_exit_during_discard_keeps_unremoved_bytes_available", "--test-threads=1"])
                .env(CHILD_ROOT, tree.root()).env(STAGE, stage).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(79),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            let session = FolderSession::open(tree.root()).unwrap();
            assert!(!session.recover(INTENT).unwrap());
            assert_eq!(tree.read("note.txt"), b"current bytes");
            match stage {
                "before" => assert_eq!(tree.read(PREVIOUS), b"previous bytes"),
                "captured" => {
                    assert_eq!(tree.read(DISCARD), b"previous bytes");
                    assert!(session.open_saved(DISCARD).unwrap().is_some());
                }
                "removed" => {
                    assert!(!tree.0.join(PREVIOUS).exists());
                    assert!(!tree.0.join(DISCARD).exists());
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn a_saved_reader_keeps_its_object_after_admission_release_and_name_replacement() {
        let tree = Tree::new();
        tree.put(PREVIOUS, b"saved bytes");
        let session = FolderSession::open(tree.root()).unwrap();
        let mut reader = session.open_saved(PREVIOUS).unwrap().unwrap();
        assert!(session.open_saved(INCOMING).unwrap().is_none());
        for bad in ["target", "../escape", ".xveil-short.previous"] {
            assert!(session.open_saved(bad).is_err());
        }
        drop(session);
        let _next = FolderSession::open(tree.root()).unwrap();
        std::fs::rename(tree.path().join(PREVIOUS), tree.path().join("moved-copy")).unwrap();
        tree.put(PREVIOUS, b"replacement at the same name");
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"saved bytes");
    }

    #[cfg(unix)]
    #[test]
    fn saved_copy_open_refuses_a_leaf_link() {
        let tree = Tree::new();
        let outside = Tree::new();
        outside.put("private", b"untouched");
        std::os::unix::fs::symlink(outside.path().join("private"), tree.path().join(PREVIOUS))
            .unwrap();
        let session = FolderSession::open(tree.root()).unwrap();
        assert!(session.open_saved(PREVIOUS).is_err());
        assert_eq!(outside.read("private"), b"untouched");
    }

    #[test]
    fn incoming_creation_makes_real_parents_and_never_adopts_an_existing_file() {
        let tree = Tree::new();
        let session = FolderSession::open(tree.root()).unwrap();
        let path = format!("one/two/{INCOMING}");
        let mut file = session.create_incoming(&path).unwrap();
        file.write_all(b"prepared").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(session.create_incoming(&path).is_err());
        assert_eq!(tree.read(&path), b"prepared");
        assert!(matches!(
            session.publish("one/two/target", &path, None).unwrap(),
            Outcome::Published(_)
        ));
        assert_eq!(tree.read("one/two/target"), b"prepared");
    }

    #[test]
    fn invalid_incoming_does_not_create_parents_or_overwrite_user_files() {
        let tree = Tree::new();
        let session = FolderSession::open(tree.root()).unwrap();
        for path in [
            "nested/user.txt",
            "nested/.xveil-short.incoming",
            "../escape",
        ] {
            assert!(session.create_incoming(path).is_err());
        }
        assert!(!tree.path().join("nested").exists());
        tree.put("file", b"user");
        assert!(
            session
                .create_incoming(&format!("file/{INCOMING}"))
                .is_err()
        );
        assert_eq!(tree.read("file"), b"user");
    }

    #[cfg(unix)]
    #[test]
    fn incoming_parent_creation_never_follows_a_link() {
        let tree = Tree::new();
        let outside = Tree::new();
        std::os::unix::fs::symlink(outside.path(), tree.path().join("redirect")).unwrap();
        let session = FolderSession::open(tree.root()).unwrap();
        assert!(
            session
                .create_incoming(&format!("redirect/new/{INCOMING}"))
                .is_err()
        );
        assert!(!outside.path().join("new").exists());
    }

    #[cfg(windows)]
    #[test]
    fn incoming_parent_creation_never_follows_a_junction() {
        let tree = Tree::new();
        let outside = Tree::new();
        let junction = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(tree.path().join("redirect"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(junction.status.success());
        let session = FolderSession::open(tree.root()).unwrap();
        assert!(
            session
                .create_incoming(&format!("redirect/new/{INCOMING}"))
                .is_err()
        );
        assert!(!outside.path().join("new").exists());
    }

    #[test]
    fn replacement_preserves_previous_and_receipt_describes_incoming() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        let incoming = tree.version(INCOMING);
        assert_eq!(
            publish(
                tree.root(),
                "target",
                INCOMING,
                Some(tree.version("target"))
            )
            .unwrap(),
            Outcome::Published(incoming)
        );
        assert_eq!(tree.read("target"), b"download");
        assert_eq!(tree.read(PREVIOUS), b"old");
        assert!(!recover(tree.root(), INTENT).unwrap());
    }

    #[test]
    fn a_scan_session_blocks_publication_in_another_subdirectory() {
        let tree = Tree::new();
        std::fs::create_dir(tree.path().join("nested")).unwrap();
        let incoming = format!("nested/{INCOMING}");
        tree.put("nested/target", b"old");
        tree.put(&incoming, b"download");
        let expected = Some(tree.version("nested/target"));
        let session = FolderSession::open(tree.root()).unwrap();
        assert!(session.matches_root(tree.root()).unwrap());
        assert_eq!(
            publish(tree.root(), "nested/target", &incoming, expected).unwrap_err(),
            "folder publication is busy"
        );
        assert_eq!(tree.read("nested/target"), b"old");
        assert!(!tree.path().join(format!("nested/{INTENT}")).exists());
        assert_eq!(child(tree.path(), "busy").status.code(), Some(74));
        drop(session);
        assert!(matches!(
            publish(tree.root(), "nested/target", &incoming, expected).unwrap(),
            Outcome::Published(_)
        ));
        assert_eq!(tree.read("nested/target"), b"download");
    }

    #[test]
    fn one_session_can_recover_then_scan_then_publish_without_unlocking() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"first download");
        let result = publish_with_hook(
            tree.root(),
            "target",
            INCOMING,
            Some(tree.version("target")),
            |stage| {
                if stage == Stage::PreviousMoved {
                    return Err("simulated interruption".to_owned());
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!tree.path().join("target").exists());
        let session = FolderSession::open(tree.root()).unwrap();
        assert!(session.recover(INTENT).unwrap());
        assert_eq!(tree.read("target"), b"old");
        let second = ".xveil-1123456789abcdef0123456789abcdef.incoming";
        tree.put(second, b"second download");
        assert!(matches!(
            session
                .publish("target", second, Some(tree.version("target")))
                .unwrap(),
            Outcome::Published(_)
        ));
        assert!(session.matches_root(tree.root()).unwrap());
        assert_eq!(tree.read("target"), b"second download");
    }

    #[test]
    fn recovery_on_the_same_handle_cannot_settle_an_in_flight_publication() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        let expected = Some(tree.version("target"));
        let session = FolderSession::open(tree.root()).unwrap();
        let mut reached = false;
        session
            .publish_with_hook("target", INCOMING, expected, |stage| {
                if stage == Stage::IntentDurable {
                    reached = true;
                    assert_eq!(
                        session.recover(INTENT).unwrap_err(),
                        "folder publication is busy"
                    );
                    assert_eq!(
                        session.publish("target", INCOMING, expected).unwrap_err(),
                        "folder publication is busy"
                    );
                    assert_eq!(tree.read(INTENT)[SETTLED_OFFSET as usize], 0);
                }
                Ok(())
            })
            .unwrap();
        assert!(reached);
        assert_eq!(tree.read("target"), b"download");
        assert_eq!(tree.read(PREVIOUS), b"old");
        assert!(!session.recover(INTENT).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_session_never_reopens_a_substituted_root_by_its_old_pathname() {
        let tree = Tree::new();
        std::fs::create_dir(tree.path().join("root")).unwrap();
        tree.put("root/target", b"old");
        tree.put(&format!("root/{INCOMING}"), b"download");
        let path = tree.path().join("root");
        let session = FolderSession::open(path.to_str().unwrap()).unwrap();
        let expected = Some(tree.version("root/target"));
        std::fs::rename(&path, tree.path().join("parked")).unwrap();
        std::fs::create_dir(&path).unwrap();
        tree.put("root/target", b"substituted root");
        assert!(!session.matches_root(path.to_str().unwrap()).unwrap());
        assert!(matches!(
            session.publish("target", INCOMING, expected).unwrap(),
            Outcome::Published(_)
        ));
        assert_eq!(tree.read("root/target"), b"substituted root");
        assert_eq!(tree.read("parked/target"), b"download");
        assert_eq!(tree.read(&format!("parked/{PREVIOUS}")), b"old");
    }

    #[test]
    fn interruption_at_every_transition_recovers_without_losing_any_version() {
        for cut in [
            Stage::IntentDurable,
            Stage::PreviousMoved,
            Stage::BeforeInstall,
            Stage::IncomingInstalled,
            Stage::Settled,
        ] {
            let tree = Tree::new();
            tree.put("target", b"old");
            tree.put(INCOMING, b"download");
            let mut reached = false;
            let result = publish_with_hook(
                tree.root(),
                "target",
                INCOMING,
                Some(tree.version("target")),
                |stage| {
                    if stage == cut {
                        reached = true;
                        return Err("simulated interruption".to_owned());
                    }
                    Ok(())
                },
            );
            assert!(reached);
            assert!(result.is_err());
            recover(tree.root(), INTENT).unwrap();
            assert!(tree.path().join("target").is_file());
            let copies: Vec<Vec<u8>> = std::fs::read_dir(tree.path())
                .unwrap()
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .collect();
            assert!(copies.iter().any(|v| v == b"old"));
            assert!(copies.iter().any(|v| v == b"download"));
            assert!(!recover(tree.root(), INTENT).unwrap());
        }
    }

    #[test]
    fn late_edit_is_preserved_and_not_certified_as_downloaded() {
        for replace in [false, true] {
            let tree = Tree::new();
            tree.put("target", b"old");
            tree.put(INCOMING, b"download");
            let mut reached = false;
            let result = publish_with_hook(
                tree.root(),
                "target",
                INCOMING,
                Some(tree.version("target")),
                |stage| {
                    if stage == Stage::IntentDurable {
                        reached = true;
                        if replace {
                            tree.put("editor-temp", b"late local edit");
                            std::fs::rename(
                                tree.path().join("editor-temp"),
                                tree.path().join("target"),
                            )
                            .unwrap();
                        } else {
                            tree.put("target", b"late local edit");
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert!(reached);
            assert_eq!(result, Outcome::LocalChanged);
            assert_eq!(tree.read("target"), b"late local edit");
            assert_eq!(tree.read(INCOMING), b"download");
        }
    }

    #[test]
    fn an_editor_holding_the_old_file_can_finish_after_backup_validation() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        let expected = Some(tree.version("target"));
        let mut editor = std::fs::OpenOptions::new()
            .write(true)
            .open(tree.path().join("target"))
            .unwrap();
        let mut reached = false;
        let result = publish_with_hook(tree.root(), "target", INCOMING, expected, |stage| {
            if stage == Stage::BeforeInstall {
                reached = true;
                editor
                    .write_all(b"late edit through an already open file")
                    .unwrap();
                editor.sync_all().unwrap();
            }
            Ok(())
        })
        .unwrap();
        assert!(reached);
        assert!(matches!(result, Outcome::Published(_)));
        assert_eq!(tree.read("target"), b"download");
        assert_eq!(
            tree.read(PREVIOUS),
            b"late edit through an already open file"
        );
        drop(editor);
    }

    #[test]
    fn a_target_created_during_a_new_file_install_wins_its_name() {
        let tree = Tree::new();
        tree.put(INCOMING, b"download");
        let mut reached = false;
        let result = publish_with_hook(tree.root(), "target", INCOMING, None, |stage| {
            if stage == Stage::BeforeInstall {
                reached = true;
                tree.put("target", b"new local file");
            }
            Ok(())
        })
        .unwrap();
        assert!(reached);
        assert_eq!(result, Outcome::LocalChanged);
        assert_eq!(tree.read("target"), b"new local file");
        assert_eq!(tree.read(INCOMING), b"download");
    }

    #[test]
    fn process_exit_at_every_transition_leaves_recoverable_files() {
        let stages = [
            Stage::IntentDurable,
            Stage::PreviousMoved,
            Stage::BeforeInstall,
            Stage::IncomingInstalled,
            Stage::Settled,
        ];
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            if std::env::var(CHILD_STAGE).unwrap() == "busy" {
                let result = recover(root.to_str().unwrap(), INTENT);
                assert!(
                    matches!(result, Err(ref message) if message == "folder publication is busy")
                );
                std::process::exit(74);
            }
            let cut: usize = std::env::var(CHILD_STAGE).unwrap().parse().unwrap();
            let root = root.to_str().unwrap();
            let parent = Parent::open(root, "target").unwrap();
            let expected = parent.version("target").unwrap();
            drop(parent);
            let result = publish_with_hook(root, "target", INCOMING, expected, |stage| {
                if stage == stages[cut] {
                    // No destructor, rollback handler or stack unwinding.
                    std::process::exit(73);
                }
                Ok(())
            });
            panic!("child did not reach the interruption boundary: {result:?}");
        }
        for cut in 0..stages.len() {
            let tree = Tree::new();
            tree.put("target", b"old");
            tree.put(INCOMING, b"download");
            let child = child(tree.path(), &cut.to_string());
            assert_eq!(
                child.status.code(),
                Some(73),
                "child must exit at the requested boundary"
            );
            recover(tree.root(), INTENT).unwrap();
            assert!(tree.path().join("target").is_file());
            let copies: Vec<Vec<u8>> = std::fs::read_dir(tree.path())
                .unwrap()
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .collect();
            assert!(copies.iter().any(|v| v == b"old"));
            assert!(copies.iter().any(|v| v == b"download"));
            assert!(!recover(tree.root(), INTENT).unwrap());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_replaced_by_a_symlink_cannot_redirect_the_transaction() {
        use std::os::unix::fs::symlink;
        let tree = Tree::new();
        let outside = Tree::new();
        std::fs::create_dir(tree.path().join("parent")).unwrap();
        tree.put("parent/target", b"old");
        tree.put(&format!("parent/{INCOMING}"), b"download");
        outside.put("target", b"outside target");
        outside.put(INCOMING, b"outside incoming");
        let expected = Some(tree.version("parent/target"));
        let mut reached = false;
        let result = publish_with_hook(
            tree.root(),
            "parent/target",
            &format!("parent/{INCOMING}"),
            expected,
            |stage| {
                if stage == Stage::IntentDurable {
                    reached = true;
                    std::fs::rename(tree.path().join("parent"), tree.path().join("parked"))
                        .unwrap();
                    symlink(outside.path(), tree.path().join("parent")).unwrap();
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(reached);
        assert!(matches!(result, Outcome::Published(_)));
        assert_eq!(tree.read("parked/target"), b"download");
        assert_eq!(tree.read(&format!("parked/{PREVIOUS}")), b"old");
        assert_eq!(outside.read("target"), b"outside target");
        assert_eq!(outside.read(INCOMING), b"outside incoming");
        assert!(recover(tree.root(), &format!("parent/{INTENT}")).is_err());
        assert!(!recover(tree.root(), &format!("parked/{INTENT}")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_target_changed_to_a_directory_or_link_is_restored_without_following_it() {
        use std::os::unix::fs::symlink;
        for link in [false, true] {
            let tree = Tree::new();
            let outside = Tree::new();
            tree.put("target", b"old");
            tree.put(INCOMING, b"download");
            outside.put("keep", b"outside data");
            let mut reached = false;
            let result = publish_with_hook(
                tree.root(),
                "target",
                INCOMING,
                Some(tree.version("target")),
                |stage| {
                    if stage == Stage::IntentDurable {
                        reached = true;
                        std::fs::rename(
                            tree.path().join("target"),
                            tree.path().join("editor-original"),
                        )
                        .unwrap();
                        if link {
                            symlink(outside.path(), tree.path().join("target")).unwrap();
                        } else {
                            std::fs::create_dir(tree.path().join("target")).unwrap();
                            tree.put("target/keep", b"new local directory");
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert!(reached);
            assert_eq!(result, Outcome::LocalChanged);
            if link {
                assert!(
                    std::fs::symlink_metadata(tree.path().join("target"))
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
            } else {
                assert_eq!(tree.read("target/keep"), b"new local directory");
            }
            assert_eq!(tree.read("editor-original"), b"old");
            assert_eq!(tree.read(INCOMING), b"download");
            assert_eq!(outside.read("keep"), b"outside data");
            assert!(!recover(tree.root(), INTENT).unwrap());
        }
    }

    #[cfg(windows)]
    #[test]
    fn an_active_lock_file_cannot_be_replaced_with_a_new_lock() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        let mut reached = false;
        publish_with_hook(
            tree.root(),
            "target",
            INCOMING,
            Some(tree.version("target")),
            |stage| {
                if stage == Stage::IntentDurable {
                    reached = true;
                    assert!(std::fs::remove_file(tree.path().join(LOCK_NAME)).is_err());
                    assert!(
                        std::fs::rename(
                            tree.path().join(LOCK_NAME),
                            tree.path().join("renamed-lock")
                        )
                        .is_err()
                    );
                    assert!(recover(tree.root(), INTENT).is_err());
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(reached);
        assert_eq!(tree.read("target"), b"download");
    }

    #[test]
    fn a_new_target_during_install_or_recovery_is_never_overwritten() {
        for interrupt in [false, true] {
            let tree = Tree::new();
            tree.put("target", b"old");
            tree.put(INCOMING, b"download");
            let mut reached = false;
            let result = publish_with_hook(
                tree.root(),
                "target",
                INCOMING,
                Some(tree.version("target")),
                |stage| {
                    if stage == Stage::PreviousMoved {
                        reached = true;
                        tree.put("target", b"new user file");
                        if interrupt {
                            return Err("simulated interruption".to_owned());
                        }
                    }
                    Ok(())
                },
            );
            assert!(reached);
            if interrupt {
                assert!(result.is_err());
                recover(tree.root(), INTENT).unwrap();
            } else {
                assert_eq!(result.unwrap(), Outcome::LocalChanged);
            }
            assert_eq!(tree.read("target"), b"new user file");
            assert_eq!(tree.read(PREVIOUS), b"old");
            assert_eq!(tree.read(INCOMING), b"download");
        }
    }

    #[test]
    fn corrupt_or_oversized_intent_is_not_empty_recovery_state() {
        for bytes in [vec![], b"corrupt".to_vec(), vec![0; MAX_INTENT_BYTES + 1]] {
            let tree = Tree::new();
            tree.put("target", b"old");
            tree.put(INTENT, &bytes);
            assert!(recover(tree.root(), INTENT).is_err());
            assert_eq!(tree.read("target"), b"old");
            assert_eq!(tree.read(INTENT), bytes);
        }
    }

    #[test]
    fn missing_target_and_missing_previous_are_an_explicit_refusal() {
        let tree = Tree::new();
        tree.put(
            INTENT,
            &Intent {
                target: "target".to_owned(),
                was_present: true,
                settled: false,
            }
            .encode()
            .unwrap(),
        );
        assert!(recover(tree.root(), INTENT).is_err());
        assert!(!tree.path().join("target").exists());
    }

    #[test]
    fn recovery_keeps_a_directory_created_at_the_target_while_offline() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        let mut reached = false;
        let result = publish_with_hook(
            tree.root(),
            "target",
            INCOMING,
            Some(tree.version("target")),
            |stage| {
                if stage == Stage::PreviousMoved {
                    reached = true;
                    return Err("simulated interruption".to_owned());
                }
                Ok(())
            },
        );
        assert!(reached);
        assert!(result.is_err());
        std::fs::create_dir(tree.path().join("target")).unwrap();
        tree.put("target/keep", b"new local directory");
        assert!(recover(tree.root(), INTENT).unwrap());
        assert_eq!(tree.read("target/keep"), b"new local directory");
        assert_eq!(tree.read(PREVIOUS), b"old");
        assert_eq!(tree.read(INCOMING), b"download");
    }

    #[cfg(windows)]
    #[test]
    fn recovery_does_not_follow_a_junction_created_at_the_target() {
        let tree = Tree::new();
        let outside = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        outside.put("keep", b"outside data");
        let mut reached = false;
        let result = publish_with_hook(
            tree.root(),
            "target",
            INCOMING,
            Some(tree.version("target")),
            |stage| {
                if stage == Stage::PreviousMoved {
                    reached = true;
                    return Err("simulated interruption".to_owned());
                }
                Ok(())
            },
        );
        assert!(reached);
        assert!(result.is_err());
        let junction = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(tree.path().join("target"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(junction.status.success());
        assert!(recover(tree.root(), INTENT).unwrap());
        assert!(
            std::fs::symlink_metadata(tree.path().join("target"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(outside.read("keep"), b"outside data");
        assert_eq!(tree.read(PREVIOUS), b"old");
        assert_eq!(tree.read(INCOMING), b"download");
    }

    #[test]
    fn new_file_can_be_published_or_cancelled_before_installation() {
        for interrupt in [false, true] {
            let tree = Tree::new();
            tree.put(INCOMING, b"download");
            let result = publish_with_hook(tree.root(), "target", INCOMING, None, |stage| {
                if interrupt && stage == Stage::IntentDurable {
                    return Err("simulated interruption".to_owned());
                }
                Ok(())
            });
            if interrupt {
                assert!(result.is_err());
                recover(tree.root(), INTENT).unwrap();
                assert_eq!(tree.read(INCOMING), b"download");
            } else {
                assert!(matches!(result.unwrap(), Outcome::Published(_)));
                assert_eq!(tree.read("target"), b"download");
            }
            assert!(!tree.path().join(PREVIOUS).exists());
        }
    }

    #[test]
    fn existing_recovery_name_is_never_adopted_or_replaced() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        tree.put(PREVIOUS, b"occupied recovery");
        assert!(
            publish(
                tree.root(),
                "target",
                INCOMING,
                Some(tree.version("target"))
            )
            .is_err()
        );
        assert_eq!(tree.read("target"), b"old");
        assert_eq!(tree.read(PREVIOUS), b"occupied recovery");
        assert_eq!(tree.read(INCOMING), b"download");
    }

    #[test]
    fn active_publisher_excludes_recovery_and_another_publisher() {
        let tree = Tree::new();
        tree.put("target", b"old");
        tree.put(INCOMING, b"download");
        let expected = Some(tree.version("target"));
        let mut reached = false;
        publish_with_hook(tree.root(), "target", INCOMING, expected, |stage| {
            if stage == Stage::IntentDurable {
                reached = true;
                assert!(recover(tree.root(), INTENT).is_err());
                assert!(publish(tree.root(), "target", INCOMING, expected).is_err());
                assert_eq!(child(tree.path(), "busy").status.code(), Some(74));
                assert_eq!(tree.read(INTENT)[SETTLED_OFFSET as usize], 0);
            }
            Ok(())
        })
        .unwrap();
        assert!(reached);
        assert_eq!(tree.read("target"), b"download");
        assert_eq!(tree.read(PREVIOUS), b"old");
    }

    #[test]
    fn journal_targets_cannot_escape_or_name_the_internal_namespace() {
        for target in [
            "",
            "../outside",
            "/absolute",
            "sub/file",
            "sub\\file",
            ".xveil-sync.lock",
            "bad\0name",
        ] {
            let tree = Tree::new();
            let mut bytes = MAGIC.to_vec();
            bytes.extend([0, 1]);
            bytes.extend((target.len() as u16).to_le_bytes());
            bytes.extend(target.as_bytes());
            tree.put(INTENT, &bytes);
            assert!(recover(tree.root(), INTENT).is_err());
            assert_eq!(tree.read(INTENT), bytes);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_colon_inside_a_posix_filename_is_not_treated_as_a_windows_stream() {
        let tree = Tree::new();
        tree.put(INCOMING, b"download");
        assert!(matches!(
            publish(tree.root(), "note:2026.txt", INCOMING, None).unwrap(),
            Outcome::Published(_)
        ));
        assert_eq!(tree.read("note:2026.txt"), b"download");
        assert!(!recover(tree.root(), INTENT).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn windows_intent_cannot_name_an_alternate_data_stream() {
        let tree = Tree::new();
        tree.put(INCOMING, b"download");
        assert!(publish(tree.root(), "note:stream", INCOMING, None).is_err());
        assert_eq!(tree.read(INCOMING), b"download");
        assert!(!tree.path().join(INTENT).exists());
        let target = b"note:stream";
        let mut bytes = MAGIC.to_vec();
        bytes.extend([0, 0]);
        bytes.extend((target.len() as u16).to_le_bytes());
        bytes.extend(target);
        tree.put(INTENT, &bytes);
        assert!(recover(tree.root(), INTENT).is_err());
    }
}
